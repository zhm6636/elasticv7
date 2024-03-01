package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/olivere/elastic/v7"
)

var ElasticClient *elastic.Client

// 搜索是经常用到的功能，经常对搜索有着不同的需求，比如搜索某个词，搜索某个分类，搜索某个价格区间，搜索多个字段，排序，聚合，搜索库存等等
// 所有有了这些需求，我们称之为搜索模块
func init() {
	certFile := "./es01.crt"
	key := "./es01.key"

	// Load certificate
	cert, err := tls.LoadX509KeyPair(certFile, key)
	if err != nil {
		log.Panic(err)
	}

	// Create a custom TLS configuration
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // Disable server certificate verification
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Implement custom verification logic here
			return nil
		},
	}

	ElasticClient, err = elastic.NewClient(elastic.SetURL("https://42.192.108.133:9200"), elastic.SetSniff(false), elastic.SetHealthcheck(true), elastic.SetBasicAuth("elastic", "Zhm5833366.."), elastic.SetHttpClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}))
	if err != nil {
		fmt.Println("elastic connect error", err)
	}
}
func main() {

	res, err := SearchForWord("test")
	if err != nil {
		panic(err)
	}
	fmt.Println(res)

}

func SearchForWord(word string) (map[string]interface{}, error) {
	result, err := ElasticClient.Search().Query(elastic.NewMatchQuery("content", word)).Do(context.Background())
	if err != nil {
		return nil, err
	}
	resultMap := make(map[string]interface{})
	b, _ := json.Marshal(result)
	json.Unmarshal(b, &resultMap)

	return resultMap, nil
}

func SearchForCategory(category string) (map[string]interface{}, error) {
	result, err := ElasticClient.Search().Query(elastic.NewMatchQuery("category", category)).Do(context.Background())
	if err != nil {
		return nil, err
	}
	resultMap := make(map[string]interface{})
	b, _ := json.Marshal(result)
	json.Unmarshal(b, &resultMap)

	return resultMap, nil
}

func SearchForPrice(start float64, stop float64) (map[string]interface{}, error) {
	result, err := ElasticClient.Search().Query(elastic.NewRangeQuery("price").Gte(start).Lte(stop)).Do(context.Background())
	if err != nil {
		return nil, err
	}
	resultMap := make(map[string]interface{})
	b, _ := json.Marshal(result)
	json.Unmarshal(b, &resultMap)

	return resultMap, nil
}

func SearchForMoreField(word string) (map[string]interface{}, error) {
	result, err := ElasticClient.Search().Query(elastic.NewMultiMatchQuery(word, "content", "name", "author")).Do(context.Background())
	if err != nil {
		return nil, err
	}
	resultMap := make(map[string]interface{})
	b, _ := json.Marshal(result)
	json.Unmarshal(b, &resultMap)

	return resultMap, nil
}

func SearchForSort() (map[string]interface{}, error) {
	result, err := ElasticClient.Search().Sort("price", false).Do(context.Background())
	if err != nil {
		return nil, err
	}
	resultMap := make(map[string]interface{})
	b, _ := json.Marshal(result)
	json.Unmarshal(b, &resultMap)

	return resultMap, nil
}

func SearchForAggregation() (map[string]interface{}, error) {
	agg := elastic.NewTermsAggregation().Field("category")
	result, err := ElasticClient.Search().Aggregation("category", agg).Do(context.Background())
	if err != nil {
		return nil, err
	}
	resultMap := make(map[string]interface{})
	b, _ := json.Marshal(result)
	json.Unmarshal(b, &resultMap)

	return resultMap, nil
}

func SearchForStock() (map[string]interface{}, error) {
	result, err := ElasticClient.Search().Query(elastic.NewRangeQuery("stock").Gt(0)).Do(context.Background())
	if err != nil {
		return nil, err
	}
	resultMap := make(map[string]interface{})
	b, _ := json.Marshal(result)
	json.Unmarshal(b, &resultMap)

	return resultMap, nil
}

//// 批量添加文档
//func AddDocToIndex(indexName string, tweets []Tweet) (int, error) {
//	bulkRequest := ElasticClient.Bulk()
//	for _, tweet := range tweets {
//		doc := elastic.NewBulkIndexRequest().Index(indexName).Doc(tweet)
//		bulkRequest = bulkRequest.Add(doc)
//	}
//	bulkResponse, err := bulkRequest.Do(context.Background())
//	if err != nil {
//		return 0, err
//	}
//	return bulkResponse.Items[0].Index.Status, nil
//}
