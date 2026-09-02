package shellprojection

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kontext-security/kontext/internal/toolcatalog"
)

func op(operation string) string { return OperationFact(operation) }

// TestOperationVocabulary pins the exact fact strings the cloud presets
// match. A rename here is a contract change for every template.
func TestOperationVocabulary(t *testing.T) {
	want := []string{
		"github/operation=force-push", "github/operation=force-push-with-lease", "github/operation=delete-ref",
		"github/operation=move-tag", "github/operation=update-ref", "github/operation=merge-pull-request",
		"github/operation=enable-auto-merge", "github/operation=disable-auto-merge", "github/operation=merge-branch",
		"github/operation=approve-pull-request", "github/operation=create-release", "github/operation=edit-release",
		"github/operation=delete-release", "github/operation=upload-release-asset", "github/operation=run-workflow",
		"github/operation=rerun-workflow-run", "github/operation=cancel-workflow-run", "github/operation=approve-workflow-run",
		"github/operation=delete-workflow-run", "github/operation=enable-workflow", "github/operation=disable-workflow",
		"github/operation=edit-repository", "github/operation=delete-repository", "github/operation=transfer-repository",
		"github/operation=edit-branch-protection", "github/operation=edit-environment", "github/operation=edit-collaborators",
		"github/operation=edit-webhooks", "github/operation=edit-deploy-keys", "github/operation=edit-secrets",
		"github/operation=other-write",
	}
	got := operationFacts([]string{
		OperationForcePush, OperationForcePushWithLease, OperationDeleteRef, OperationMoveTag, OperationUpdateRef,
		OperationMergePullRequest, OperationEnableAutoMerge, OperationDisableAutoMerge, OperationMergeBranch,
		OperationApprovePullRequest, OperationCreateRelease, OperationEditRelease, OperationDeleteRelease,
		OperationUploadReleaseAsset, OperationRunWorkflow, OperationRerunWorkflowRun, OperationCancelWorkflowRun,
		OperationApproveWorkflowRun, OperationDeleteWorkflowRun, OperationEnableWorkflow, OperationDisableWorkflow,
		OperationEditRepository, OperationDeleteRepository, OperationTransferRepository, OperationEditBranchProtection,
		OperationEditEnvironment, OperationEditCollaborators, OperationEditWebhooks, OperationEditDeployKeys,
		OperationEditSecrets, OperationOtherWrite,
	})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("vocabulary = %v, want %v", got, want)
	}
	if got := toolcatalog.Operations(toolcatalog.GitHubToolPrefix + "merge_pull_request"); !reflect.DeepEqual(got, []string{OperationMergePullRequest}) {
		t.Fatalf("toolcatalog merge operations = %v", got)
	}
}

// TestGitHistoryOperations covers the protect-git-history vocabulary.
func TestGitHistoryOperations(t *testing.T) {
	deleteRef, forceOp, lease, moveTag, updateRef := op(OperationDeleteRef), op(OperationForcePush), op(OperationForcePushWithLease), op(OperationMoveTag), op(OperationUpdateRef)
	runCorpus(t, []corpusCase{
		{name: "plain push", command: "git push origin main", programs: []string{"git"}, facts: []string{write}, absentFacts: []string{deleteRef, forceOp, lease}, complete: true},
		{name: "push tags", command: "git push --tags origin", programs: []string{"git"}, facts: []string{write}, absentFacts: []string{deleteRef, forceOp}, complete: true},
		{name: "push feature branch", command: "git push origin feature", programs: []string{"git"}, facts: []string{write}, absentFacts: []string{deleteRef}, complete: true},
		{name: "force short", command: "git push -f origin main", programs: []string{"git"}, facts: []string{forcePush, forceOp}, absentFacts: []string{lease, deleteRef}, complete: true},
		{name: "force refspec", command: "git push origin +main:main", programs: []string{"git"}, facts: []string{forcePush, forceOp}, absentFacts: []string{deleteRef}, complete: true},
		{name: "force with lease", command: "git push --force-with-lease origin main", programs: []string{"git"}, facts: []string{write, lease}, absentFacts: []string{forcePush, forceOp}, complete: true},
		{name: "force with lease value", command: "git push --force-with-lease=main:abc origin main", programs: []string{"git"}, facts: []string{lease}, absentFacts: []string{forcePush}, complete: true},
		{name: "force if includes", command: "git push --force-if-includes --force-with-lease origin main", programs: []string{"git"}, facts: []string{lease}, absentFacts: []string{forcePush}, complete: true},
		{name: "delete long", command: "git push origin --delete feature", programs: []string{"git"}, facts: []string{write, deleteRef}, absentFacts: []string{forceOp}, complete: true},
		{name: "delete short", command: "git push -d origin feature", programs: []string{"git"}, facts: []string{deleteRef}, complete: true},
		{name: "delete in cluster", command: "git push -fd origin feature", programs: []string{"git"}, facts: []string{deleteRef, forceOp, forcePush}, complete: true},
		{name: "empty source refspec", command: "git push origin :feature", programs: []string{"git"}, facts: []string{deleteRef}, absentFacts: []string{forceOp}, complete: true},
		{name: "empty source tag refspec", command: "git push origin :refs/tags/v1.0", programs: []string{"git"}, facts: []string{deleteRef}, complete: true},
		{name: "forced empty source refspec", command: "git push origin +:refs/tags/v1", programs: []string{"git"}, facts: []string{deleteRef, forceOp}, complete: true},
		{name: "bare colon pushes matching", command: "git push origin :", programs: []string{"git"}, facts: []string{write}, absentFacts: []string{deleteRef}, complete: true},
		{name: "prune", command: "git push --prune origin", programs: []string{"git"}, facts: []string{deleteRef}, absentFacts: []string{forceOp}, complete: true},
		{name: "mirror", command: "git push --mirror origin", programs: []string{"git"}, facts: []string{deleteRef, forceOp, forcePush}, complete: true},
		{name: "dry run delete", command: "git push -n --delete origin feature", programs: []string{"git"}, facts: []string{"github/dry-run=true"}, absentFacts: []string{deleteRef, write}, complete: true},
		{name: "dry run lease", command: "git push --dry-run --force-with-lease origin main", programs: []string{"git"}, absentFacts: []string{lease, forceOp}, complete: true},
		{name: "gh merge delete branch", command: "gh pr merge 42 --delete-branch", programs: []string{"gh"}, facts: []string{op(OperationMergePullRequest), deleteRef}, complete: true},
		{name: "gh merge -d cluster", command: "gh pr merge 42 -sd", programs: []string{"gh"}, facts: []string{op(OperationMergePullRequest), deleteRef}, complete: true},
		{name: "gh release delete cleanup tag", command: "gh release delete v1.2.0 --cleanup-tag", programs: []string{"gh"}, facts: []string{op(OperationDeleteRelease), deleteRef}, complete: true},
		{name: "gh release delete keeps tag", command: "gh release delete v1.2.0 -y", programs: []string{"gh"}, facts: []string{op(OperationDeleteRelease)}, absentFacts: []string{deleteRef}, complete: true},
		{name: "gh repo sync force", command: "gh repo sync --force", programs: []string{"gh"}, facts: []string{forceOp}, absentFacts: []string{forcePush}, complete: true},
		{name: "gh repo sync", command: "gh repo sync", programs: []string{"gh"}, facts: []string{op(OperationOtherWrite)}, absentFacts: []string{forceOp}, complete: true},
		{name: "api delete ref", command: "gh api -X DELETE repos/acme/api/git/refs/heads/old", programs: []string{"gh"}, facts: []string{deleteRef, catalogued}, features: []string{FeatureOperationFromRoute}, complete: true},
		{name: "api delete ref full url", command: "gh api -X DELETE https://api.github.com/repos/acme/api/git/refs/heads/old", programs: []string{"gh"}, facts: []string{deleteRef}, complete: true},
		{name: "api delete ref placeholders", command: "gh api -X DELETE repos/{owner}/{repo}/git/refs/heads/old", programs: []string{"gh"}, facts: []string{deleteRef}, complete: true},
		{name: "api get ref", command: "gh api repos/acme/api/git/refs/heads/old", programs: []string{"gh"}, absentFacts: []string{deleteRef, write, op(OperationOtherWrite)}, complete: true},
		{name: "api move tag", command: "gh api -X PATCH repos/acme/api/git/refs/tags/v1 -f sha=abc", programs: []string{"gh"}, facts: []string{moveTag}, absentFacts: []string{forceOp, updateRef}, complete: true},
		{name: "api forced move tag", command: "gh api -X PATCH repos/acme/api/git/refs/tags/v1 -f sha=abc -f force=true", programs: []string{"gh"}, facts: []string{moveTag, forceOp, forcePush}, complete: true},
		{name: "api fast forward ref", command: "gh api -X PATCH repos/acme/api/git/refs/heads/main -f sha=abc", programs: []string{"gh"}, facts: []string{updateRef}, absentFacts: []string{forceOp, moveTag, op(OperationOtherWrite)}, complete: true},
		{name: "api forced ref", command: "gh api repos/acme/api/git/refs/heads/main -X PATCH -f force=true", programs: []string{"gh"}, facts: []string{forceOp, forcePush}, absentFacts: []string{updateRef}, complete: true},
		{name: "api delete ref-ish segment", command: "gh api -X DELETE repos/acme/api/git/refs-archive/heads/old", programs: []string{"gh"}, facts: []string{op(OperationOtherWrite)}, absentFacts: []string{deleteRef}, complete: true},
		{name: "curl delete ref", command: "curl -X DELETE https://api.github.com/repos/acme/api/git/refs/heads/x", programs: []string{"curl"}, facts: []string{deleteRef}, features: []string{FeatureOperationFromRoute}, complete: true},
		{name: "curl force", command: `curl -X PATCH -d '{"force":true}' https://api.github.com/repos/acme/api/git/refs/heads/main`, programs: []string{"curl"}, facts: []string{forcePush, forceOp}, absentFacts: []string{updateRef}, complete: true},
		{name: "graphql delete ref", command: `gh api graphql -f query='mutation { deleteRef(input: {refId: "R_1"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{deleteRef, catalogued}, features: []string{FeatureOperationFromGraphQL}, complete: true},
		{name: "graphql forced update ref", command: `gh api graphql -f query='mutation { updateRef(input: {refId: "R_1", oid: "abc", force: true}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{forceOp}, absentFacts: []string{updateRef, forcePush}, complete: true},
		{name: "graphql tag move", command: `gh api graphql -f query='mutation { updateRef(input: {refId: "refs/tags/v1", oid: "abc"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{moveTag}, absentFacts: []string{forceOp}, complete: true},
		{name: "graphql fast forward", command: `gh api graphql -f query='mutation { updateRef(input: {refId: "R_1", oid: "abc"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{updateRef}, absentFacts: []string{forceOp, moveTag}, complete: true},
	})
}

// TestHumanMergeOperations covers the require-human-merge vocabulary.
func TestHumanMergeOperations(t *testing.T) {
	merge, auto, disableAuto, mergeBranch, approve, other := op(OperationMergePullRequest), op(OperationEnableAutoMerge), op(OperationDisableAutoMerge), op(OperationMergeBranch), op(OperationApprovePullRequest), op(OperationOtherWrite)
	runCorpus(t, []corpusCase{
		{name: "pr merge", command: "gh pr merge 42", programs: []string{"gh"}, facts: []string{"gh/command=pr/merge", write, merge}, absentFacts: []string{auto, other}, complete: true},
		{name: "pr merge squash", command: "gh pr merge 42 --squash", programs: []string{"gh"}, facts: []string{merge}, complete: true},
		{name: "pr merge via repo flag", command: "gh --repo acme/api pr merge 42", programs: []string{"gh"}, facts: []string{merge}, complete: true},
		{name: "pr merge auto", command: "gh pr merge 42 --auto --squash", programs: []string{"gh"}, facts: []string{auto}, absentFacts: []string{merge}, complete: true},
		{name: "pr merge disable auto", command: "gh pr merge 42 --disable-auto", programs: []string{"gh"}, facts: []string{disableAuto}, absentFacts: []string{merge, auto}, complete: true},
		{name: "pr view", command: "gh pr view 42", programs: []string{"gh"}, facts: []string{"gh/command=pr/view"}, absentFacts: []string{merge, write, other}, complete: true},
		{name: "pr create", command: "gh pr create --title x --body y", programs: []string{"gh"}, facts: []string{"gh/command=pr/create", write, other}, absentFacts: []string{merge}, complete: true},
		{name: "pr edit", command: "gh pr edit 42 --add-label ready", programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{merge}, complete: true},
		{name: "pr review approve", command: "gh pr review 42 --approve", programs: []string{"gh"}, facts: []string{approve}, absentFacts: []string{merge, other}, complete: true},
		{name: "pr review approve short", command: "gh pr review 42 -a", programs: []string{"gh"}, facts: []string{approve}, complete: true},
		{name: "pr review comment", command: "gh pr review 42 --comment -b lgtm", programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{approve}, complete: true},
		{name: "api merge", command: "gh api -X PUT repos/o/r/pulls/42/merge", programs: []string{"gh"}, facts: []string{merge, catalogued}, complete: true},
		{name: "api merge with input body", command: "gh api -X PUT repos/acme/api/pulls/42/merge --input body.json", programs: []string{"gh"}, facts: []string{merge, unrecognized}, complete: false},
		{name: "api get pull", command: "gh api repos/o/r/pulls/42", programs: []string{"gh"}, absentFacts: []string{merge, write, other}, complete: true},
		{name: "api merge-ish segment", command: "gh api -X PUT repos/o/r/pulls/42/merge-ish", programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{merge}, complete: true},
		{name: "api update branch", command: "gh api -X PUT repos/acme/api/pulls/42/update-branch", programs: []string{"gh"}, facts: []string{write, other}, absentFacts: []string{merge}, complete: true},
		{name: "api edit pull", command: "gh api -X PATCH repos/acme/api/pulls/42 -f title=x", programs: []string{"gh"}, facts: []string{write, other}, absentFacts: []string{merge}, complete: true},
		{name: "api merge branch", command: "gh api -X POST repos/acme/api/merges -f base=main -f head=feat", programs: []string{"gh"}, facts: []string{mergeBranch}, complete: true},
		{name: "api merge upstream", command: "gh api repos/acme/api/merge-upstream -f branch=main", programs: []string{"gh"}, facts: []string{mergeBranch}, complete: true},
		{name: "api approve review", command: "gh api repos/acme/api/pulls/42/reviews -f event=APPROVE", programs: []string{"gh"}, facts: []string{approve}, absentFacts: []string{other}, complete: true},
		{name: "api comment review", command: "gh api repos/acme/api/pulls/42/reviews -f event=COMMENT", programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{approve}, complete: true},
		{name: "api submit approve event", command: "gh api repos/acme/api/pulls/42/reviews/7/events -f event=APPROVE", programs: []string{"gh"}, facts: []string{approve}, complete: true},
		{name: "curl merge", command: `curl -X PUT -d '{"merge_method":"squash"}' https://api.github.com/repos/acme/api/pulls/42/merge`, programs: []string{"curl"}, facts: []string{merge}, complete: true},
		{name: "curl approve", command: `curl -d '{"event":"APPROVE"}' https://api.github.com/repos/acme/api/pulls/42/reviews`, programs: []string{"curl"}, facts: []string{approve}, complete: true},
		{name: "curl read pull", command: "curl https://api.github.com/repos/acme/api/pulls/42", programs: []string{"curl"}, absentFacts: []string{merge, other}, complete: true},
		{name: "graphql merge", command: `gh api graphql -f query='mutation { mergePullRequest(input: {pullRequestId: "PR_1"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{merge}, complete: true},
		{name: "graphql enqueue", command: `gh api graphql --raw-field query='mutation Enqueue($id: ID!) { enqueuePullRequest(input: {pullRequestId: $id}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{merge}, absentFacts: []string{other}, complete: true},
		{name: "graphql enable auto merge", command: `gh api graphql -f query='mutation { enablePullRequestAutoMerge(input:{pullRequestId:"X"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{auto}, complete: true},
		{name: "graphql disable auto merge", command: `gh api graphql -f query='mutation { disablePullRequestAutoMerge(input:{pullRequestId:"X"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{disableAuto}, absentFacts: []string{auto, merge}, complete: true},
		{name: "graphql approve review", command: `gh api graphql -f query='mutation { addPullRequestReview(input: {pullRequestId: "X", event: APPROVE}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{approve}, complete: true},
		{name: "graphql comment review", command: `gh api graphql -f query='mutation { addPullRequestReview(input: {pullRequestId: "X", event: COMMENT}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{approve}, complete: true},
		{name: "graphql query is a read", command: `gh api graphql -f query='query { viewer { login } }'`, programs: []string{"gh"}, facts: []string{write, catalogued}, absentFacts: []string{merge, other}, complete: true},
		{name: "graphql query from file", command: "gh api graphql -f query=@m.graphql", programs: []string{"gh"}, facts: []string{unrecognized}, absentFacts: []string{merge, other}, features: []string{FeatureGraphQLNotLiteral}, complete: false},
		{name: "graphql query from variable", command: `gh api graphql -f query="$Q"`, programs: []string{"gh"}, facts: []string{unrecognized}, absentFacts: []string{merge}, features: []string{FeatureGraphQLNotLiteral}, complete: false},
		{name: "graphql input body", command: "gh api graphql --input body.json", programs: []string{"gh"}, facts: []string{unrecognized}, absentFacts: []string{merge}, complete: false},
		{name: "graphql unknown mutation", command: `gh api graphql -f query='mutation { addComment(input: {subjectId: "X", body: "hi"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{merge}, complete: true},
		{name: "curl graphql merge", command: `curl -X POST -d '{"query":"mutation { mergePullRequest(input: {pullRequestId: \"PR_1\"}) { clientMutationId } }"}' https://api.github.com/graphql`, programs: []string{"curl"}, facts: []string{merge}, complete: true},
		{name: "curl graphql from file", command: "curl -d @m.json https://api.github.com/graphql", programs: []string{"curl"}, facts: []string{unrecognized}, absentFacts: []string{merge, other}, features: []string{FeatureGraphQLNotLiteral}, complete: false},
	})
}

// TestReleaseAndWorkflowOperations covers protect-releases-and-workflows.
func TestReleaseAndWorkflowOperations(t *testing.T) {
	other := op(OperationOtherWrite)
	runCorpus(t, []corpusCase{
		{name: "release list", command: "gh release list", programs: []string{"gh"}, facts: []string{"gh/command=release/list", catalogued}, absentFacts: []string{write, op(OperationCreateRelease)}, complete: true},
		{name: "release create", command: "gh release create v1", programs: []string{"gh"}, facts: []string{op(OperationCreateRelease)}, absentFacts: []string{other}, complete: true},
		{name: "release create notes", command: "gh release create v1.2.0 --notes x", programs: []string{"gh"}, facts: []string{op(OperationCreateRelease)}, complete: true},
		{name: "release edit", command: "gh release edit v1.2.0 --draft=false", programs: []string{"gh"}, facts: []string{op(OperationEditRelease)}, complete: true},
		{name: "release upload", command: "gh release upload v1.2.0 dist.zip", programs: []string{"gh"}, facts: []string{op(OperationUploadReleaseAsset)}, complete: true},
		{name: "release delete asset", command: "gh release delete-asset v1.2.0 dist.zip", programs: []string{"gh"}, facts: []string{op(OperationDeleteRelease)}, complete: true},
		{name: "release download", command: "gh release download v1.2.0", programs: []string{"gh"}, absentFacts: []string{write, op(OperationDeleteRelease)}, complete: true},
		{name: "api create release", command: "gh api repos/acme/api/releases -f tag_name=v1", programs: []string{"gh"}, facts: []string{op(OperationCreateRelease), "http/method=POST"}, complete: true},
		{name: "api list releases", command: "gh api repos/acme/api/releases", programs: []string{"gh"}, absentFacts: []string{op(OperationCreateRelease), other}, complete: true},
		{name: "api generate notes", command: "gh api -X POST repos/acme/api/releases/generate-notes -f tag_name=v1", programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{op(OperationCreateRelease), op(OperationEditRelease)}, complete: true},
		{name: "api edit release", command: "gh api -X PATCH repos/acme/api/releases/1 -f name=x", programs: []string{"gh"}, facts: []string{op(OperationEditRelease)}, complete: true},
		{name: "api edit release asset", command: "gh api -X PATCH repos/acme/api/releases/assets/9 -f name=x", programs: []string{"gh"}, facts: []string{op(OperationEditRelease)}, complete: true},
		{name: "api delete release", command: "gh api -X DELETE repos/acme/api/releases/1", programs: []string{"gh"}, facts: []string{op(OperationDeleteRelease)}, complete: true},
		{name: "api delete release asset", command: "gh api -X DELETE repos/acme/api/releases/assets/9", programs: []string{"gh"}, facts: []string{op(OperationDeleteRelease)}, complete: true},
		{name: "curl upload asset", command: "curl -sS -T asset.zip https://uploads.github.com/repos/acme/api/releases/1/assets", programs: []string{"curl"}, facts: []string{op(OperationUploadReleaseAsset), "http/method=PUT"}, complete: true},
		{name: "curl post asset", command: "curl -X POST --data-binary @asset.zip https://uploads.github.com/repos/acme/api/releases/1/assets?name=x", programs: []string{"curl"}, facts: []string{op(OperationUploadReleaseAsset)}, complete: false},
		{name: "api host asset path is not upload", command: "gh api -X POST repos/acme/api/releases/1/assets", programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{op(OperationUploadReleaseAsset)}, complete: true},
		{name: "workflow run", command: "gh workflow run ci.yml", programs: []string{"gh"}, facts: []string{op(OperationRunWorkflow)}, absentFacts: []string{other}, complete: true},
		{name: "workflow run inputs", command: "gh workflow run ci.yml -f env=prod", programs: []string{"gh"}, facts: []string{op(OperationRunWorkflow)}, complete: true},
		{name: "workflow list", command: "gh workflow list", programs: []string{"gh"}, absentFacts: []string{op(OperationRunWorkflow), write}, complete: true},
		{name: "workflow enable", command: "gh workflow enable ci.yml", programs: []string{"gh"}, facts: []string{op(OperationEnableWorkflow)}, complete: true},
		{name: "workflow disable", command: "gh workflow disable ci.yml", programs: []string{"gh"}, facts: []string{op(OperationDisableWorkflow)}, complete: true},
		{name: "run rerun", command: "gh run rerun 123 --failed", programs: []string{"gh"}, facts: []string{op(OperationRerunWorkflowRun)}, complete: true},
		{name: "run cancel", command: "gh run cancel 123", programs: []string{"gh"}, facts: []string{op(OperationCancelWorkflowRun)}, complete: true},
		{name: "run delete", command: "gh run delete 123", programs: []string{"gh"}, facts: []string{op(OperationDeleteWorkflowRun)}, complete: true},
		{name: "run view", command: "gh run view 123 --log", programs: []string{"gh"}, facts: []string{"gh/command=run/view"}, absentFacts: []string{write, op(OperationRerunWorkflowRun)}, complete: true},
		{name: "api dispatch workflow", command: "gh api -X POST repos/acme/api/actions/workflows/ci.yml/dispatches -f ref=main", programs: []string{"gh"}, facts: []string{op(OperationRunWorkflow)}, complete: true},
		{name: "api repository dispatch", command: "gh api -X POST repos/acme/api/dispatches -f event_type=deploy", programs: []string{"gh"}, facts: []string{op(OperationRunWorkflow)}, complete: true},
		{name: "api get workflow", command: "gh api repos/acme/api/actions/workflows/ci.yml", programs: []string{"gh"}, absentFacts: []string{op(OperationRunWorkflow), other}, complete: true},
		{name: "api rerun", command: "gh api -X POST repos/acme/api/actions/runs/123/rerun", programs: []string{"gh"}, facts: []string{op(OperationRerunWorkflowRun)}, complete: true},
		{name: "api rerun failed jobs", command: "gh api -X POST repos/acme/api/actions/runs/123/rerun-failed-jobs", programs: []string{"gh"}, facts: []string{op(OperationRerunWorkflowRun)}, complete: true},
		{name: "api rerun job", command: "gh api -X POST repos/acme/api/actions/jobs/9/rerun", programs: []string{"gh"}, facts: []string{op(OperationRerunWorkflowRun)}, complete: true},
		{name: "api cancel", command: "gh api -X POST repos/acme/api/actions/runs/123/cancel", programs: []string{"gh"}, facts: []string{op(OperationCancelWorkflowRun)}, complete: true},
		{name: "api force cancel", command: "gh api -X POST repos/acme/api/actions/runs/123/force-cancel", programs: []string{"gh"}, facts: []string{op(OperationCancelWorkflowRun)}, complete: true},
		{name: "api approve run", command: "gh api -X POST repos/acme/api/actions/runs/123/approve", programs: []string{"gh"}, facts: []string{op(OperationApproveWorkflowRun)}, complete: true},
		{name: "api approve pending deployment", command: "gh api -X POST repos/acme/api/actions/runs/123/pending_deployments -f state=approved", programs: []string{"gh"}, facts: []string{op(OperationApproveWorkflowRun)}, complete: true},
		{name: "api deployment protection rule", command: "gh api -X POST repos/acme/api/actions/runs/123/deployment_protection_rule -f state=approved", programs: []string{"gh"}, facts: []string{op(OperationApproveWorkflowRun)}, complete: true},
		{name: "api delete run", command: "gh api -X DELETE repos/acme/api/actions/runs/123", programs: []string{"gh"}, facts: []string{op(OperationDeleteWorkflowRun)}, complete: true},
		{name: "api delete run logs", command: "gh api -X DELETE repos/acme/api/actions/runs/123/logs", programs: []string{"gh"}, facts: []string{op(OperationDeleteWorkflowRun)}, complete: true},
		{name: "api delete artifact", command: "gh api -X DELETE repos/acme/api/actions/artifacts/5", programs: []string{"gh"}, facts: []string{op(OperationDeleteWorkflowRun)}, complete: true},
		{name: "api get run", command: "gh api repos/acme/api/actions/runs/123", programs: []string{"gh"}, absentFacts: []string{op(OperationDeleteWorkflowRun), other}, complete: true},
		{name: "api enable workflow", command: "gh api -X PUT repos/acme/api/actions/workflows/ci.yml/enable", programs: []string{"gh"}, facts: []string{op(OperationEnableWorkflow)}, absentFacts: []string{op(OperationDisableWorkflow)}, complete: true},
		{name: "api disable workflow", command: "gh api -X PUT repos/acme/api/actions/workflows/7/disable", programs: []string{"gh"}, facts: []string{op(OperationDisableWorkflow)}, complete: true},
		{name: "curl rerun", command: "curl -X POST https://api.github.com/repos/acme/api/actions/runs/123/rerun", programs: []string{"curl"}, facts: []string{op(OperationRerunWorkflowRun)}, complete: true},
		{name: "push tag", command: "git push origin v1.2.0", programs: []string{"git"}, facts: []string{write}, absentFacts: []string{op(OperationCreateRelease)}, complete: true},
	})
}

// TestRepositorySettingsOperations covers protect-repository-settings.
func TestRepositorySettingsOperations(t *testing.T) {
	other := op(OperationOtherWrite)
	runCorpus(t, []corpusCase{
		{name: "repo view", command: "gh repo view acme/api", programs: []string{"gh"}, facts: []string{"gh/command=repo/view"}, absentFacts: []string{write, op(OperationEditRepository)}, complete: true},
		{name: "repo edit", command: "gh repo edit --visibility private", programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, absentFacts: []string{other}, complete: true},
		{name: "repo edit default branch", command: "gh repo edit --default-branch main", programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "repo rename", command: "gh repo rename new-name", programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "repo archive", command: "gh repo archive acme/api -y", programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "repo unarchive", command: "gh repo unarchive acme/api -y", programs: []string{"gh"}, facts: []string{"gh/command=repo/unarchive", write, op(OperationEditRepository)}, absentFacts: []string{unrecognized}, complete: true},
		{name: "repo delete", command: "gh repo delete acme/api --yes", programs: []string{"gh"}, facts: []string{op(OperationDeleteRepository)}, absentFacts: []string{op(OperationEditRepository)}, complete: true},
		{name: "repo create", command: "gh repo create acme/new --private", programs: []string{"gh"}, facts: []string{"gh/command=repo/create", other}, absentFacts: []string{op(OperationEditRepository)}, complete: true},
		{name: "deploy key add", command: "gh repo deploy-key add key.pub", programs: []string{"gh"}, facts: []string{"gh/command=repo/deploy-key/add", write, op(OperationEditDeployKeys)}, complete: true},
		{name: "deploy key delete", command: "gh repo deploy-key delete 123", programs: []string{"gh"}, facts: []string{op(OperationEditDeployKeys)}, complete: true},
		{name: "deploy key list", command: "gh repo deploy-key list", programs: []string{"gh"}, facts: []string{"gh/command=repo/deploy-key/list", catalogued}, absentFacts: []string{write, op(OperationEditDeployKeys)}, complete: true},
		{name: "autolink create", command: "gh repo autolink create TICKET- 'https://x/<num>'", programs: []string{"gh"}, facts: []string{"gh/command=repo/autolink/create", op(OperationEditRepository)}, complete: true},
		{name: "autolink list", command: "gh repo autolink list", programs: []string{"gh"}, facts: []string{catalogued}, absentFacts: []string{write}, complete: true},
		{name: "secret set", command: "gh secret set X", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "secret set body", command: "gh secret set NPM_TOKEN --body x", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "secret delete", command: "gh secret delete NPM_TOKEN", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "secret list", command: "gh secret list", programs: []string{"gh"}, facts: []string{"gh/command=secret/list"}, absentFacts: []string{write, op(OperationEditSecrets)}, complete: true},
		{name: "variable set env", command: "gh variable set FOO --env prod --body bar", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "variable delete", command: "gh variable delete FOO", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "api edit repo", command: "gh api -X PATCH repos/acme/api -f allow_force_pushes=true", programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, absentFacts: []string{op(OperationDeleteRepository), forcePush}, complete: true},
		{name: "api get repo", command: "gh api repos/acme/api", programs: []string{"gh"}, absentFacts: []string{op(OperationEditRepository), other}, complete: true},
		{name: "api delete repo", command: "gh api -X DELETE repos/acme/api", programs: []string{"gh"}, facts: []string{op(OperationDeleteRepository)}, absentFacts: []string{op(OperationEditRepository)}, complete: true},
		{name: "api delete deeper path is not repo", command: "gh api -X DELETE repos/acme/api/issues/1/labels/bug", programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{op(OperationDeleteRepository)}, complete: true},
		{name: "api transfer", command: "gh api -X POST repos/acme/api/transfer -f new_owner=x", programs: []string{"gh"}, facts: []string{op(OperationTransferRepository)}, complete: true},
		{name: "api topics", command: "gh api -X PUT repos/acme/api/topics -f names[]=x", programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "api pages", command: "gh api -X POST repos/acme/api/pages -f build_type=workflow", programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "api actions permissions", command: "gh api -X PUT repos/acme/api/actions/permissions/workflow -f default_workflow_permissions=read", programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "api vulnerability alerts", command: "gh api -X DELETE repos/acme/api/vulnerability-alerts", programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "api branch protection input", command: "gh api -X PUT repos/acme/api/branches/main/protection --input p.json", programs: []string{"gh"}, facts: []string{op(OperationEditBranchProtection), unrecognized}, complete: false},
		{name: "api delete branch protection", command: "gh api -X DELETE repos/acme/api/branches/main/protection", programs: []string{"gh"}, facts: []string{op(OperationEditBranchProtection)}, complete: true},
		{name: "api required reviews", command: "gh api -X PATCH repos/acme/api/branches/main/protection/required_pull_request_reviews -f required_approving_review_count=2", programs: []string{"gh"}, facts: []string{op(OperationEditBranchProtection)}, complete: true},
		{name: "api get branch protection", command: "gh api repos/acme/api/branches/main/protection", programs: []string{"gh"}, absentFacts: []string{op(OperationEditBranchProtection), other}, complete: true},
		{name: "api create ruleset", command: "gh api repos/acme/api/rulesets -f name=x", programs: []string{"gh"}, facts: []string{op(OperationEditBranchProtection)}, complete: true},
		{name: "api delete ruleset", command: "gh api -X DELETE repos/acme/api/rulesets/5", programs: []string{"gh"}, facts: []string{op(OperationEditBranchProtection)}, complete: true},
		{name: "api rename branch", command: "gh api -X POST repos/acme/api/branches/main/rename -f new_name=trunk", programs: []string{"gh"}, facts: []string{op(OperationEditBranchProtection)}, complete: true},
		{name: "api environment", command: "gh api -X PUT repos/acme/api/environments/prod", programs: []string{"gh"}, facts: []string{op(OperationEditEnvironment)}, complete: true},
		{name: "api deployment branch policy", command: "gh api -X POST repos/acme/api/environments/prod/deployment-branch-policies -f name=main", programs: []string{"gh"}, facts: []string{op(OperationEditEnvironment)}, complete: true},
		{name: "api environment secret", command: "gh api -X PUT repos/acme/api/environments/prod/secrets/TOKEN -f encrypted_value=x", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, absentFacts: []string{op(OperationEditEnvironment)}, complete: true},
		{name: "api collaborator", command: "gh api -X PUT repos/acme/api/collaborators/bob -f permission=admin", programs: []string{"gh"}, facts: []string{op(OperationEditCollaborators)}, complete: true},
		{name: "api remove collaborator", command: "gh api -X DELETE repos/acme/api/collaborators/bob", programs: []string{"gh"}, facts: []string{op(OperationEditCollaborators)}, complete: true},
		{name: "api invitation", command: "gh api -X PATCH repos/acme/api/invitations/3 -f permissions=write", programs: []string{"gh"}, facts: []string{op(OperationEditCollaborators)}, complete: true},
		{name: "api team repo", command: "gh api -X PUT orgs/acme/teams/core/repos/acme/api -f permission=push", programs: []string{"gh"}, facts: []string{op(OperationEditCollaborators)}, complete: true},
		{name: "api webhook", command: "gh api repos/acme/api/hooks -f config[url]=https://x", programs: []string{"gh"}, facts: []string{op(OperationEditWebhooks)}, complete: true},
		{name: "api webhook config", command: "gh api -X PATCH repos/acme/api/hooks/7/config -f url=https://y", programs: []string{"gh"}, facts: []string{op(OperationEditWebhooks)}, complete: true},
		{name: "api list webhooks", command: "gh api repos/acme/api/hooks", programs: []string{"gh"}, absentFacts: []string{op(OperationEditWebhooks), other}, complete: true},
		{name: "api deploy key", command: "gh api repos/acme/api/keys -f key=ssh-ed25519...", programs: []string{"gh"}, facts: []string{op(OperationEditDeployKeys)}, complete: true},
		{name: "api delete deploy key", command: "gh api -X DELETE repos/acme/api/keys/12", programs: []string{"gh"}, facts: []string{op(OperationEditDeployKeys)}, complete: true},
		{name: "api repo secret", command: "gh api -X PUT repos/acme/api/actions/secrets/TOKEN -f encrypted_value=x", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "api repo variable", command: "gh api repos/acme/api/actions/variables -f name=FOO -f value=bar", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "api dependabot secret", command: "gh api -X DELETE repos/acme/api/dependabot/secrets/TOKEN", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "api org secret", command: "gh api -X PUT orgs/acme/actions/secrets/TOKEN -f encrypted_value=x", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "api org variable", command: "gh api -X PATCH orgs/acme/actions/variables/FOO -f value=x", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "api user codespaces secret", command: "gh api -X PUT user/codespaces/secrets/TOKEN -f encrypted_value=x", programs: []string{"gh"}, facts: []string{op(OperationEditSecrets)}, complete: true},
		{name: "api list secrets", command: "gh api repos/acme/api/actions/secrets", programs: []string{"gh"}, absentFacts: []string{op(OperationEditSecrets), other}, complete: true},
		{name: "api create issue", command: "gh api repos/acme/api/issues -f title=x", programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{op(OperationEditRepository)}, complete: true},
		{name: "api edit org", command: "gh api -X PATCH orgs/acme -f description=x", programs: []string{"gh"}, facts: []string{other}, absentFacts: []string{op(OperationEditRepository)}, complete: true},
		{name: "api enterprise host", command: "gh api -X DELETE https://ghe.example.com/api/v3/repos/acme/api", programs: []string{"gh"}, facts: []string{write}, absentFacts: []string{op(OperationDeleteRepository), other}, complete: true},
		{name: "curl delete repo", command: "curl -X DELETE https://api.github.com/repos/o/r", programs: []string{"curl"}, facts: []string{op(OperationDeleteRepository)}, complete: true},
		{name: "curl edit repo", command: `curl -X PATCH -d '{"private":true}' https://api.github.com/repos/acme/api`, programs: []string{"curl"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "curl edit repo with query", command: `curl -X PATCH -d '{"private":true}' "https://api.github.com/repos/acme/api?x=1"`, programs: []string{"curl"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "curl read repo", command: "curl https://api.github.com/repos/acme/api", programs: []string{"curl"}, absentFacts: []string{op(OperationEditRepository), other}, complete: true},
		{name: "curl other host", command: `curl -X DELETE https://example.com/repos/o/r`, programs: []string{"curl"}, absentFacts: []string{op(OperationDeleteRepository), other, write}, complete: true},
		{name: "graphql update repository", command: `gh api graphql -f query='mutation { updateRepository(input: {repositoryId: "R", hasWikiEnabled: false}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "graphql archive repository", command: `gh api graphql -f query='mutation { archiveRepository(input: {repositoryId: "R"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{op(OperationEditRepository)}, complete: true},
		{name: "graphql branch protection rule", command: `gh api graphql -f query='mutation { createBranchProtectionRule(input: {repositoryId: "R", pattern: "main"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{op(OperationEditBranchProtection)}, complete: true},
		{name: "graphql ruleset", command: `gh api graphql -f query='mutation { deleteRepositoryRuleset(input: {repositoryRulesetId: "X"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{op(OperationEditBranchProtection)}, complete: true},
		{name: "graphql two mutations", command: `gh api graphql -f query='mutation { a: mergePullRequest(input: {pullRequestId: "P"}) { clientMutationId } b: deleteRef(input: {refId: "R"}) { clientMutationId } }'`, programs: []string{"gh"}, facts: []string{op(OperationMergePullRequest), op(OperationDeleteRef)}, complete: true},
	})
}

func TestGraphQLMutationFields(t *testing.T) {
	tests := []struct {
		query string
		want  []string
	}{
		{`mutation { mergePullRequest(input: {pullRequestId: "X"}) { clientMutationId } }`, []string{"mergePullRequest"}},
		{`mutation M($id: ID!) { deleteRef(input: {refId: $id}) { clientMutationId } }`, []string{"deleteRef"}},
		{`mutation { a: updateRef(input: {refId: "x", oid: "y"}) { ref { name } } b: deleteRef(input: {refId: "z"}) { clientMutationId } }`, []string{"updateRef", "deleteRef"}},
		{`query { repository(owner: "o", name: "r") { id } }`, nil},
		{`mutation { updateRef(input: {refId: "a", oid: "b"}) { ref { target { ... on Commit { history(first: 1) { totalCount } } } } } }`, []string{"updateRef"}},
		{`mutation { x(input: {body: "mutation { deleteRef(input: {refId: \"a\"}) }"}) { id } }`, []string{"x"}},
		{`mutation {`, nil},
	}
	for _, test := range tests {
		if got := graphqlMutationFields(test.query); !reflect.DeepEqual(got, test.want) {
			t.Errorf("graphqlMutationFields(%q) = %v, want %v", test.query, got, test.want)
		}
	}
}

func TestMatchSegments(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"repos/*/*", "repos/o/r", true},
		{"repos/*/*", "repos/o/r/hooks", false},
		{"repos/*/*", "repos//r", false},
		{"repos/*/*/pulls/*/merge", "repos/o/r/pulls/42/merge", true},
		{"repos/*/*/pulls/*/merge", "repos/o/r/pulls/42/merge-ish", false},
		{"repos/*/*/pulls/*/merge", "repos/o/r/pulls/42/merge/x", false},
		{"repos/*/*/git/refs/**", "repos/o/r/git/refs", false},
		{"repos/*/*/git/refs/**", "repos/o/r/git/refs/heads", true},
		{"repos/*/*/git/refs/**", "repos/o/r/git/refs/heads/feature/x", true},
		{"repos/*/*/hooks", "repos/{owner}/{repo}/hooks", true},
	}
	for _, test := range tests {
		got := matchSegments(pathSegments(test.pattern), pathSegments(test.path))
		if got != test.want {
			t.Errorf("matchSegments(%q, %q) = %t, want %t", test.pattern, test.path, got, test.want)
		}
	}
}

func TestGraphqlMutationFieldsIgnoresCommentsAndStrings(t *testing.T) {
	cases := map[string][]string{
		"# mutation {\nmutation { deleteRef(input: {refId: \"x\"}) { clientMutationId } }":               {"deleteRef"},
		"mutation { updateRef(input: {refId: \"mutation { deleteRef }\"}) { clientMutationId } }":        {"updateRef"},
		"mutation { createIssue(input: {body: \"\"\"mutation {\n deleteRef\n\"\"\"}) { issue { id } } }": {"createIssue"},
		"# only a comment mentioning mutation { deleteRef }":                                             nil,
	}
	for query, want := range cases {
		if got := graphqlMutationFields(query); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%q: fields = %v, want %v", query, got, want)
		}
	}
}

func TestGraphqlMutationFieldsHonoursEscapedBlockStringQuotes(t *testing.T) {
	query := "mutation { createIssue(input: {body: \"\"\"quote \\\"\"\" mutation { deleteRef }\"\"\"}) { issue { id } } }\n" +
		"mutation { updateRef(input: {}) { clientMutationId } }"
	want := []string{"createIssue", "updateRef"}
	if got := graphqlMutationFields(query); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("fields = %v, want %v", got, want)
	}
}
