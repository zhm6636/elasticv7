package elastic7

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/olivere/elastic/v7"
)

type ElasticConn struct {
	*elastic.Client
}

var ElasticClient ElasticConn
var ctx = context.Background()

func NewConn(url string, username, password string) ElasticConn {
	certFile := "./conf/elasticsearch.crt"
	key := "./conf/elasticsearch.key"
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
	ElasticClient.Client, err = elastic.NewClient(elastic.SetURL("https://"+url), elastic.SetSniff(false), elastic.SetHealthcheck(true), elastic.SetBasicAuth(username, password), elastic.SetHttpClient(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}))
	if err != nil {
		fmt.Println("elastic connect error", err)
	}
	return ElasticClient
}

// 索引是否存在
// indexName 索引的名字
func (c *ElasticConn) ExistIndex(indexName string) (bool, error) {
	exists, err := c.Client.IndexExists(indexName).Do(ctx)
	return exists, err
}

// 创建索引
// indexName 索引的名字
func (c *ElasticConn) CreateIndex(indexName string, mapping string) (*elastic.IndicesCreateResult, error) {

	createIndex, err := c.Client.CreateIndex(indexName).BodyString(mapping).Do(ctx)

	return createIndex, err
}

// 向索引写入单条数据
func (c *ElasticConn) AddDocToIndex(indexName string, doc interface{}) (*elastic.IndexResponse, error) {
	put1, err := c.Client.Index().
		Index(indexName).
		//Id(strconv.Itoa(doc.Id)).
		BodyJson(doc).
		Do(ctx)

	return put1, err
}

// 根据文档id查询数据
func (c *ElasticConn) SearchDocByDocID(indexName string, id int) (*elastic.GetResult, error) {
	// Get tweet with specified ID
	get1, err := c.Client.Get().
		Index(indexName).
		Id(strconv.Itoa(id)).
		Do(ctx)
	return get1, err
}

// 词项精确查询,term是精确查询，字段类型keyword 不能是text
func (c *ElasticConn) TermQuery(indexName, field, value string, offset, limit int) (*elastic.SearchResult, error) {
	termQuery := elastic.NewTermQuery(field, value)
	searchResult, err := c.Client.Search().
		Index(indexName).         // search in index "twitter"
		Query(termQuery).         // specify the query
		From(offset).Size(limit). // take documents 0-9
		Pretty(true).             // pretty print request and response JSON
		Do(ctx)                   // execute

	return searchResult, err
}

//更新
