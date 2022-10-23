package global

import (
	"github.com/jaeles-project/jaeles/libs"
	"sync"
)

type ScanStatistics struct {
	ScanId        string
	RequestsCount int
	RespnseTime   float64
	StatusCodes   map[int]int
	Vulns         []libs.Vuln
	Errs          []error
}

var ScanStatisticsMap = make(map[string]*ScanStatistics)
var lock sync.RWMutex

func Statistics(scanId string, respTime float64, statusCode int, err error) {
	lock.RLock()
	statistics, ok := ScanStatisticsMap[scanId]
	if !ok {
		lock.RUnlock()
		lock.Lock()
		defer lock.Unlock()

		if _, ok := ScanStatisticsMap[scanId]; !ok {
			statistics = &ScanStatistics{
				ScanId:      scanId,
				StatusCodes: make(map[int]int),
			}
			ScanStatisticsMap[scanId] = statistics
		}
	} else {
		lock.RUnlock()
	}

	statistics.RequestsCount++
	statistics.RespnseTime += respTime
	statistics.StatusCodes[statusCode]++
	if err != nil {
		statistics.Errs = append(statistics.Errs, err)
	}
}

func GetStatistics(scanId string) *ScanStatistics {
	lock.RLock()
	defer lock.RUnlock()
	return ScanStatisticsMap[scanId]
}

func ClearStatistics(scanId string) {
	lock.Lock()
	defer lock.Unlock()

	delete(ScanStatisticsMap, scanId)
}

func AddVuln(v libs.Vuln) {
	lock.RLock()
	defer lock.RUnlock()

	statistics, ok := ScanStatisticsMap[v.ScanId]
	if !ok {
		return
	}

	statistics.Vulns = append(statistics.Vulns, v)
}
