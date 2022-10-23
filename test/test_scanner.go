package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/scanner"
	"github.com/jaeles-project/jaeles/server"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
)

func main() {
	// 读取你需要加载的poc
	file, err := os.Open("test-signatures/statuscode-fuzz.yaml")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	// 将poc传给scanner进行加载，一个poc对应一个id，后续可根据这个id确定调用哪个poc。
	scanner, err := scanner.NewScanner(map[uint]string{1: string(content)})
	if err != nil {
		panic(err)
	}

	req, _ := http.NewRequest("GET", "http://www.moj.gov.cn/?test=request", nil)
	var body []byte
	if req.Body != nil {
		// 如果请求有body的话，需要读取这个body
		body, _ = io.ReadAll(req.Body)
	}
	// 克隆一个新的request，用于获取http请求的raw数据。
	r2 := req.Clone(req.Context())
	r2.Body = io.NopCloser(bytes.NewBuffer(body))
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	// 获取响应信息
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	// 获取request、response的dump数据，并将这个数据传给scanner，用于漏洞扫描。
	requestDump, _ := httputil.DumpRequestOut(r2, true)
	responseDump, _ := httputil.DumpResponse(resp, true)
	reqData := []server.RequestData{
		{
			RawReq: base64.StdEncoding.EncodeToString(requestDump),
			RawRes: base64.StdEncoding.EncodeToString(responseDump),
			URL:    req.URL.String(),
		},
	}
	// 设置扫描ID
	scanId := uuid.New().String()
	// 进行漏洞扫描
	err = scanner.ScanWithMultipleTargetsAndSignatures(reqData, []uint{1}, libs.WithScanId(scanId), libs.WithEnableFiltering())
	if err != nil {
		panic(err)
	}
	fmt.Println("scanId: ", scanId)
	// 获取扫描结果
	result, err := scanner.GetScanResult(scanId)
	rb, err := json.Marshal(result)
	fmt.Println(string(rb))
	// 清除扫描结果
	scanner.ClearScanResult(scanId)
}
