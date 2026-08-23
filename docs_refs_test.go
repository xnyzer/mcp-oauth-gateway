package main

// Reference guard (F-026a). The repository points at itself constantly: Go
// comments cite "SPEC §1.5", tests cite "CODING-STANDARDS §9", and code and
// documentation alike cite requirement IDs like SR-8. None of those pointers is
// checked by the compiler, so a renamed heading or a retired requirement ID
// leaves silent dead references behind. This test resolves every one of them.
//
// It lives in the root package because it checks repository documents rather
// than any one package's code, and it runs under the ordinary `go test ./...`
// invocation that CI already uses — no new tooling, no new dependency.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// Floors, not expected values. They exist so that a walk which silently stops
// finding files fails loudly instead of passing with zero checks. Ordinary
// editing moves the real counts around; only a collapse trips these.
const (
	minSectionRefs     = 100
	minRequirementRefs = 100
	minRequirementDefs = 20
)

// Documents whose numbered headings can be cited as "<name> §N.M".
var referencedDocs = []string{"SPEC.md", "CODING-STANDARDS.md"}

// registerDocs are the documents allowed to define requirement IDs. Exactly one
// of them may do so at a time, so that a register split across two documents —
// the state this repository spent its first year in — fails loudly.
var registerDocs = []string{"SPEC.md", "REQUIREMENTS.md"}

var (
	// "SPEC §1.11.3", "SPEC.md §2.3" — naming the document is required, because
	// a bare section sign is ambiguous here: "§7" means CODING-STANDARDS §7 in some
	// files, a section of the spec in others, and part of an RFC citation in a
	// third set. Only the explicit form is guarded — see the coverage note at
	// the end of this file for what that deliberately leaves out.
	sectionRefRe = regexp.MustCompile(`(SPEC|CODING-STANDARDS)(?:\.md)? §([0-9]+(?:\.[0-9]+)*)`)

	// "FR-1", "GR-5", "SR-11" anywhere in code or prose.
	requirementRefRe = regexp.MustCompile(`\b(FR|GR|SR)-([0-9]+)\b`)

	// A definition line in the register: "- **SR-5 DCR abuse mitigation.** …".
	// The title follows the ID inside the bold run, which is what separates a
	// definition from a narrative mention like "- **FR-2** reframed from …".
	requirementDefRe = regexp.MustCompile(`(?m)^- \*\*(FR|GR|SR)-([0-9]+)[ .]`)

	// Numbered Markdown heading: "## 2. Data model", "### 1.11 Protected proxy".
	headingRe = regexp.MustCompile(`^(#{1,6}) ([0-9]+(?:\.[0-9]+)*)\.? `)

	// A top-level ordered list item: the "3." of "3. **Upstream forwarding…**".
	// These are what a third-level reference such as §1.11.3 points at.
	orderedItemRe = regexp.MustCompile(`^([0-9]+)\. `)

	// Relative Markdown link target: the "SPEC.md" in "[the spec](SPEC.md#x)".
	mdLinkRe = regexp.MustCompile(`\]\(([^)\s]+)\)`)
)

type repoFile struct {
	path string // slash-separated, relative to the repository root
	body string
}

// readRepoFiles returns every text file tracked by git. "Tracked" is the right
// definition of the repository here: it keeps local, gitignored artefacts (the
// operator's `private/` notes, regenerated audit output) from failing a test
// about the repository's own documents, and it makes the reported counts
// reproducible on any checkout.
func readRepoFiles(t *testing.T) []repoFile {
	t.Helper()

	const maxFileSize = 4 << 20

	out, err := exec.Command("git", "ls-files", "-z").Output()
	require.NoError(t, err, "listing tracked files (this guard needs a git checkout)")

	var files []repoFile
	for _, name := range bytes.Split(out, []byte{0}) {
		if len(name) == 0 {
			continue
		}
		path := filepath.FromSlash(string(name))
		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Size() > maxFileSize {
			continue // deleted in the working tree, a submodule, or too big to be prose
		}
		raw, err := os.ReadFile(path)
		if err != nil || !utf8.Valid(raw) {
			continue // binaries carry no references
		}
		files = append(files, repoFile{path: filepath.ToSlash(path), body: string(raw)})
	}
	require.NotEmpty(t, files, "git listed no tracked text files at all")
	return files
}

// section is one numbered heading of a document, plus the number of top-level
// ordered list items in its body — the items a third-level reference points at.
type section struct {
	items int
}

// indexSections maps every numbered heading of a document to its section. A
// missing document yields nil, which makes every reference to it fail with a
// readable message rather than panicking.
func indexSections(doc string) map[string]section {
	raw, err := os.ReadFile(doc)
	if err != nil {
		return nil
	}

	sections := make(map[string]section)
	current := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if m := headingRe.FindStringSubmatch(line); m != nil {
			current = m[2]
			sections[current] = section{}
			continue
		}
		if current == "" {
			continue
		}
		// Only the highest item number matters, and lists in this repository are
		// written 1., 2., 3. — so the count is the largest number seen before the
		// section's own body ends at the next heading.
		if m := orderedItemRe.FindStringSubmatch(line); m != nil {
			n, err := strconv.Atoi(m[1])
			if err == nil && n > sections[current].items {
				sections[current] = section{items: n}
			}
		}
	}
	return sections
}

// resolveSectionRef decides whether "§1.11.3" points at something real.
//
// A reference resolves when it names a heading outright, or when it names a
// list item inside one: "SPEC §1.11.3" means ordered item 3 of §1.11, which is
// not a heading of its own. The item is counted, not assumed — accepting any
// reference whose *parent* exists would let a renamed §1.11 keep passing as
// "item 11 of §1", which is exactly the rename this guard has to catch.
func resolveSectionRef(ref string, sections map[string]section) bool {
	if _, ok := sections[ref]; ok {
		return true
	}
	cut := strings.LastIndex(ref, ".")
	if cut < 0 {
		return false
	}
	parent, ok := sections[ref[:cut]]
	if !ok {
		return false
	}
	item, err := strconv.Atoi(ref[cut+1:])
	return err == nil && item >= 1 && item <= parent.items
}

func TestSectionReferencesResolve(t *testing.T) {
	indexed := make(map[string]map[string]section, len(referencedDocs))
	for _, doc := range referencedDocs {
		sections := indexSections(doc)
		require.NotEmpty(t, sections, "%s has no numbered headings — the guard cannot check it", doc)
		indexed[doc] = sections
	}

	total := 0
	perDoc := map[string]int{}
	for _, f := range readRepoFiles(t) {
		for _, m := range sectionRefRe.FindAllStringSubmatch(f.body, -1) {
			doc, ref := m[1]+".md", m[2]
			total++
			perDoc[doc]++
			require.Truef(t, resolveSectionRef(ref, indexed[doc]),
				"%s cites %s §%s, which is not a section of %s nor a list item inside one", f.path, m[1], ref, doc)
		}
	}

	t.Logf("resolved %d section references (%s)", total, countsByKey(perDoc))
	require.GreaterOrEqual(t, total, minSectionRefs, "far fewer section references than this repository has — the walk or the pattern broke")
}

func TestRequirementReferencesResolve(t *testing.T) {
	defined := map[string]bool{}
	var registers []string
	for _, doc := range registerDocs {
		raw, err := os.ReadFile(doc)
		if err != nil {
			continue
		}
		found := requirementDefRe.FindAllStringSubmatch(string(raw), -1)
		if len(found) == 0 {
			continue
		}
		registers = append(registers, doc)
		for _, m := range found {
			defined[m[1]+"-"+m[2]] = true
		}
	}
	require.Lenf(t, registers, 1,
		"exactly one document may define the FR/GR/SR register, found %v — a move left the register in two places", registers)
	require.GreaterOrEqual(t, len(defined), minRequirementDefs, "the register defines almost nothing — the definition pattern broke")

	total := 0
	for _, f := range readRepoFiles(t) {
		// The register itself is scanned too: its definition lines resolve
		// against themselves, and skipping it would leave the citations in its
		// own contract text unchecked — which is most of them.
		for _, m := range requirementRefRe.FindAllStringSubmatch(f.body, -1) {
			id := m[1] + "-" + m[2]
			total++
			require.Truef(t, defined[id],
				"%s cites %s, which %s does not define", f.path, id, registers[0])
		}
	}

	t.Logf("resolved %d requirement references against %d IDs defined in %s", total, len(defined), registers[0])
	require.GreaterOrEqual(t, total, minRequirementRefs, "far fewer requirement references than this repository has — the walk or the pattern broke")
}

// TestDocumentLinksResolve catches the other way a reference dies: a Markdown
// link to a document that no longer exists. External links are not fetched.
func TestDocumentLinksResolve(t *testing.T) {
	total := 0
	for _, f := range readRepoFiles(t) {
		if !strings.HasSuffix(f.path, ".md") {
			continue
		}
		dir := filepath.Dir(f.path)
		for _, m := range mdLinkRe.FindAllStringSubmatch(f.body, -1) {
			target := m[1]
			if strings.HasPrefix(target, "#") || strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			if anchor := strings.IndexByte(target, '#'); anchor >= 0 {
				target = target[:anchor]
			}
			if target == "" {
				continue
			}
			total++
			_, err := os.Stat(filepath.Join(dir, filepath.FromSlash(target)))
			require.NoErrorf(t, err, "%s links to %s, which does not exist", f.path, target)
		}
	}
	t.Logf("resolved %d relative document links", total)
}

// countsByKey renders a stable "SPEC.md=304, CODING-STANDARDS.md=21" summary.
func countsByKey(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strconv.Itoa(counts[k]))
	}
	return strings.Join(parts, ", ")
}

// What this guard deliberately does not cover, so the gap is on the record
// rather than discovered later:
//
//   - Bare section signs ("§6", "§1.12") without a document name. They resolve by
//     context — usually CODING-STANDARDS in package code, the spec in the spec —
//     and no rule separates them reliably. Citing the document is the fix.
//   - RFC citations ("RFC 8252 §7.3"). Resolving those means fetching the RFC.
//   - The *wording* of a list item, only that the item exists: renumbering the
//     items inside a section without changing how many there are goes unnoticed.
//   - Heading anchors in Markdown links ("SPEC.md#some-heading"); only the file
//     part is resolved.
