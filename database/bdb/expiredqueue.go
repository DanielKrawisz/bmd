package bdb

import (
	"time"

	"github.com/DanielKrawisz/bmutil/hash"
)

// expiration represents a map from index to
type expiration struct {
	exp  time.Time
	hash *hash.Sha
}

// expiredQueue implements heap.Interface and holds expirations.
type expiredQueue []*expiration

func (pq expiredQueue) Len() int { return len(pq) }

func (pq expiredQueue) Less(i, j int) bool {
	return pq[i].exp.Before(pq[j].exp)
}

func (pq expiredQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *expiredQueue) Push(x interface{}) {
	item := x.(*expiration)
	*pq = append(*pq, item)
}

func (pq *expiredQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

func (pq *expiredQueue) Peek() *expiration {
	if len(*pq) == 0 {
		return nil
	}
	return (*pq)[0]
}
