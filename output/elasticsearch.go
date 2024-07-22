package output

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/codevault-llc/certshield/types"
	"github.com/codevault-llc/certshield/utils"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
)

var ElasticSearch *elasticsearch.Client

var IndexName = "codevault_source-" + time.Now().Format("2006.01.02")

func InitElasticSearch() {
	url	:= os.Getenv("ELASTICSEARCH_URL")
	apiKey := os.Getenv("ELASTICSEARCH_APIKEY")

	cfg := elasticsearch.Config{
		Addresses: []string{
			url,
		},
		APIKey: apiKey,
	}
	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		utils.Logger.Error(
			"Error creating Elasticsearch client",
			slog.String("error", err.Error()),
		)
	}

	utils.Logger.Info(
		"Created Elasticsearch client",
		slog.String("url", url),
	)
	res, err := es.Info()
	if err != nil {
		utils.Logger.Error(
			"Error getting response from Elasticsearch",
			slog.String("error", err.Error()),
		)
	}
	defer res.Body.Close()

	utils.Logger.Info(
		"Elasticsearch client created",
	)
	ElasticSearch = es
}

func SendToElasticSearch(data types.LogMessage) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		utils.Logger.Error(
			"Error marshalling log message",
			slog.String("error", err.Error()),
		)
	}

	req := esapi.IndexRequest{
		Index: 		IndexName,
		DocumentID: "",
		Body: 		bytes.NewReader(dataBytes),
		Refresh: 	"true",

		Pretty: true,
	}

	res, err := req.Do(context.Background(), ElasticSearch)
		if err != nil {
			utils.Logger.Error("Error getting response from Elasticsearch", slog.String("error", err.Error()))
		}
		defer res.Body.Close()

		if res.IsError() {
			utils.Logger.Error("Error indexing document", slog.String("error", res.String()))
		}
}
