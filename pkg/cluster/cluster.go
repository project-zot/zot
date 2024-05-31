package cluster

import "github.com/dchest/siphash"

// computes the target member using siphash and returns the index and the member
// siphash was chosen to prevent against hash attacks where an attacker
// can target all requests to one given instance instead of balancing across the cluster
// resulting in a Denial-of-Service (DOS).
// ref: https://en.wikipedia.org/wiki/SipHash
func ComputeTargetMember(hashKey string, members []string, repoName string) (uint64, string) {
	h := siphash.New([]byte(hashKey))
	h.Write([]byte(repoName))
	sum64 := h.Sum64()
	targetIdx := sum64 % uint64(len(members))

	return targetIdx, members[targetIdx]
}
