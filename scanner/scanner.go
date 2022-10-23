package scanner

import (
	"encoding/base64"
	"fmt"
	"github.com/jaeles-project/jaeles/cmd"
	"github.com/jaeles-project/jaeles/core"
	"github.com/jaeles-project/jaeles/global"
	"github.com/jaeles-project/jaeles/libs"
	"github.com/jaeles-project/jaeles/server"
	"github.com/panjf2000/ants/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const concurrency = 20

type Scanner struct {
	// Signatures is the list of signatures to use for scanning.
	// Singnature's type is map[string]*libs.Signature
	Signatures atomic.Value
}

func NewScanner(signContents map[uint]string) (*Scanner, error) {
	signatureMap, err := parseSignatures(signContents)
	if err != nil {
		return nil, err
	}

	var signatures atomic.Value
	signatures.Store(signatureMap)
	return &Scanner{Signatures: signatures}, nil
}

func parseSignatures(signs map[uint]string) (signatureMap map[uint]libs.Signature, err error) {
	signatureMap = make(map[uint]libs.Signature, len(signs))
	for id, sign := range signs {
		signature, err := core.ParseSignFromContent(sign)
		if err != nil {
			return nil, err
		}
		signature.ID = strconv.FormatUint(uint64(id), 10) // 重置签名ID
		signatureMap[id] = signature
	}
	return
}

func (s *Scanner) UpdateSignatures(signContents map[uint]string) error {
	signatureMap, err := parseSignatures(signContents)
	if err != nil {
		return err
	}

	s.Signatures.Store(signatureMap)
	return nil
}

func (s *Scanner) ScanWithMultipleTargetsAndSignatures(reqDatas []server.RequestData, signatureIds []uint, ooption ...libs.OOption) error {
	signatures := s.Signatures.Load().(map[uint]libs.Signature)
	selectedSignatures := make([]libs.Signature, 0, len(signatureIds))
	unknownSignatureIds := make([]uint, 0, len(signatureIds))
	for _, signatureId := range signatureIds {
		if signature, ok := signatures[signatureId]; ok {
			selectedSignatures = append(selectedSignatures, signature)
		} else {
			unknownSignatureIds = append(unknownSignatureIds, signatureId)
		}
	}
	if len(unknownSignatureIds) > 0 {
		unknownSignatureIdStrs := make([]string, 0, len(unknownSignatureIds))
		for _, unknownSignatureId := range unknownSignatureIds {
			unknownSignatureIdStrs = append(unknownSignatureIdStrs, fmt.Sprintf("%d", unknownSignatureId))
		}
		return fmt.Errorf("未知的poc: %v", strings.Join(unknownSignatureIdStrs, ", "))
	}

	records := make([]libs.Record, 0, len(reqDatas))
	for _, reqData := range reqDatas {
		var record libs.Record
		req, err := base64.StdEncoding.DecodeString(reqData.RawReq)
		if err != nil {
			return err
		}

		record.OriginReq = core.ParseBurpRequest(string(req))
		if reqData.URL != "" {
			record.OriginReq.URL = reqData.URL
		}
		if reqData.RawRes != "" {
			res, err := base64.StdEncoding.DecodeString(reqData.RawRes)
			if err != nil {
				return err
			}
			record.OriginRes = core.ParseBurpResponse(string(req), string(res))
		}
		records = append(records, record)
	}

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(concurrency, func(i interface{}) {
		cmd.CreateRunnerWithOOption(i, ooption...)
		wg.Done()
	}, ants.WithPreAlloc(true))
	defer p.Release()

	for _, record := range records {
		for _, sign := range selectedSignatures {
			// parse sign as list or single
			var url string
			if sign.Type != "fuzz" {
				url = record.OriginReq.URL
			} else {
				fuzzSign := sign
				fuzzSign.Requests = []libs.Request{}
				for _, req := range sign.Requests {
					core.ParseRequestFromServer(&record, req, sign)
					// override the original if these field defined in signature
					if req.Method == "" {
						req.Method = record.OriginReq.Method
					}
					if req.URL == "" {
						req.URL = record.OriginReq.URL
					}
					if len(req.Headers) == 0 {
						req.Headers = record.OriginReq.Headers
					}
					if req.Body == "" {
						req.Body = record.OriginReq.Body
					}
					fuzzSign.Requests = append(fuzzSign.Requests, req)
				}
				url = record.OriginReq.URL
				sign = fuzzSign
			}

			// single routine
			wg.Add(1)
			job := libs.Job{URL: url, Sign: sign}
			_ = p.Invoke(job)
		}
	}
	wg.Wait()
	return nil
}

func (s *Scanner) GetScanResult(scanId string) (global.ScanStatistics, error) {
	result := global.GetStatistics(scanId)
	if result == nil {
		return global.ScanStatistics{}, fmt.Errorf("扫描结果不存在")
	}
	return *result, nil
}

func (s *Scanner) ClearScanResult(scanId string) {
	global.ClearStatistics(scanId)
}
