package scanner

import (
	"bufio"
	"net/http"
	"sync"
)

var filterList []string
var once sync.Once

func InitList() {
	once.Do(fetchList)
}

func fetchList() {
	url := "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt"

	resp, err := http.Get(url)
	if err != nil {
		panic("Failed to fetch filter list: " + err.Error())
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		filterList = append(filterList, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		panic("Error reading filter list: " + err.Error())
	}
}

func ScanToURL(url string) bool {
	for _, filteredURL := range filterList {
		if url == filteredURL {
			return true
		}
	}
	return false
}
