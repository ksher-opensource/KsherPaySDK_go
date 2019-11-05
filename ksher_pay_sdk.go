/*
@Time   : 2019-05-17 10:52
@Author : apei
@Desc   : 
*/

package KsherGo

import (
	"fmt"
	"time"
	"sort"
	"errors"
	"strconv"
	"strings"
	"io/ioutil"
	"net/http"
	"net/url"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
    math_rand "math/rand"
)

const (
	//PayDomain    =  "https://api.mch.ksher.net/KsherPay"
	PayDomain    =  "http://ht.dspread.com/front/KsherPay"
	Version      =  "v3.0.0" // SDK version
)

type Client struct {
	AppId            string   // ksher appid
	PrivateKey       []byte	  // 商户私钥
	PublicKey        []byte	  // ksher公钥
}

type KsherResp struct {
	Code             int                        `json:"code"`
	Msg              string						`json:"msg"`
	StatusCode       string						`json:"status_code"`
	StatusMsg        string						`json:"status_msg"`
	Sign             string						`json:"sign"`         //16进制字符串
	Version			 string					    `json:"version"`
	TimeStamp		 string						`json:"time_stamp"`
	Data             map[string]interface{}		`json:"data"`
}

// New creates a new client.
//
// appId
// privateKey
// publicKey
//
// Client    creates the new client instance, the returned value is valid when error is nil.
// error    it's nil if no error, otherwise it's an error object.
func New(appId string, privateKey []byte) *Client {
	// Ksher client
	client := &Client{
		AppId:       appId,
		PrivateKey:  privateKey,
		PublicKey:   []byte(`
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL7955OCuN4I8eYNL/mixZWIXIgCvIVE
ivlxqdpiHPcOLdQ2RPSx/pORpsUu/E9wz0mYS2PY7hNc2mBgBOQT+wUCAwEAAQ==
-----END PUBLIC KEY-----`),
	}

	return client
}

// 生成随机数
func GetNonceStr(num int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	l := len(letters)
	r := math_rand.New(math_rand.NewSource(time.Now().UnixNano()))
	b := make([]rune, num)
	for i := range b {
		b[i] = letters[r.Intn(l)]
	}
	return string(b)
}
//时间戳
func GetTimeStamp() string {
	return time.Now().Format("20060102150405")
}
/*
签名
1.参数名排序
2.key1=valuekey2=value
3.appid=mch20027auth_code=12345channel=wechatfee_type=THBmch_order_no=2019051614001nonce_str=BpLnoperator_id=001time_stamp=20190517174933total_fee=100
*/
func KsherSign(params url.Values, privateKeyData []byte) (sign string, err error) {
	var keys []string
	for key := range params {
		if key != "sign" {
			keys = append(keys, key + "=" + params.Get(key))
		}
	}
	sort.Strings(keys)
	stringToSign := strings.Join(keys, "")
	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return sign, errors.New("private key error")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return sign, err
	}
	hash := md5.New()
	hash.Write([]byte(stringToSign))
	hashed := hash.Sum(nil)
	signByte, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.MD5, hashed)
	//sign_base := base64.StdEncoding.EncodeToString(sign_byte)
	//sign_hex := hex.EncodeToString(sign_byte)
	sign = fmt.Sprintf("%x", signByte)
	fmt.Println(stringToSign)
	fmt.Println(sign)
	return sign, nil
}
//签名检验
func KsherVerify(resp KsherResp, publicKeyData []byte) error {
	sign, err := hex.DecodeString(resp.Sign)
	var keys []string
	for key, value := range resp.Data {
		fmt.Println(value)
		if key == "sign"{
			//sign = fmt.Sprintf("%x", value)
		} else {
			keys = append(keys, key + "=" + value.(string))
		}
	}
	sort.Strings(keys)
	stringToSign := strings.Join(keys, "")
	dataByte := []byte(stringToSign)

	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		return errors.New("public key error")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	hash := md5.New()
	hash.Write(dataByte)
	hashed := hash.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.MD5, hashed, sign)
}
//post 请求
func KsherPost(url string, postValue url.Values, privateKeyData, publicKey []byte)  (KsherResp,error){
	response := KsherResp{Code:-1}
	sign, err := KsherSign(postValue, privateKeyData)
	if err != nil {
		return response, err
	}
	postValue.Add("sign", sign)
	req, err := http.NewRequest("POST", url, strings.NewReader(postValue.Encode()))
	if err != nil {
		return response, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	defer resp.Body.Close()
	if err != nil || resp.StatusCode != 200{
		// handle error
		return response, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return response, err
	}
	responseStr := string(body)
	fmt.Println(responseStr)
	if err = json.Unmarshal(body, &response); err != nil {
		fmt.Printf("Unmarshal err, %v\n", err)
		return response, err
	}
	//json.NewDecoder(resp.Body).Decode(&response)
	if response.Code == 0{
		err = KsherVerify(response, publicKey)
		if err == nil{
			return response, nil
		}else {
			return response, err
		}
	}

	return response, nil
}

/*
商户扫用户(B扫C)
:mchOrderNo: 商户订单号
:feeType: 支付币种 'THB'
:authCode: 支付条码
:channel: 支付通道 wechat aplipay
:operatorId: 操作员编号
:totalFee: 支付金额
:return:
*/
func (client Client) QuickPay(mchOrderNo, feeType, authCode, channel,operatorId string, totalFee int) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
		"total_fee": {strconv.Itoa(totalFee)},
		"fee_type": {feeType},
		"auth_code": {authCode},
		"channel": {channel},
		"operator_id": {operatorId},
	}
	return KsherPost(PayDomain+"/quick_pay", postValue, client.PrivateKey, client.PublicKey)
}
/*
C扫B支付
:param kwargs:
必传参数
	mch_order_no
	total_fee
	fee_type
	channel
选传参数
	redirect_url
	notify_url
	paypage_title
	operator_id
:return:
*/
func (client Client) JsApiPay(mchOrderNo, feeType, channel string, totalFee int) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
		"total_fee": {strconv.Itoa(totalFee)},
		"fee_type": {feeType},
		"channel": {channel},
	}
	return KsherPost(PayDomain+"/jsapi_pay", postValue, client.PrivateKey, client.PublicKey)
}
/*
动态码支付
:param kwargs:
必传参数
	mch_order_no
	total_fee
	fee_type
	channel
选传参数
	redirect_url
	notify_url
	paypage_title
	product
	attach
	operator_id
	device_id
	img_type
:return:
*/
func (client Client) NativePay(mchOrderNo, feeType, channel string, totalFee int) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
		"total_fee": {strconv.Itoa(totalFee)},
		"fee_type": {feeType},
		"channel": {channel},
	}
	return KsherPost(PayDomain+"/native_pay", postValue, client.PrivateKey, client.PublicKey)
}
/*
小程序支付
:param kwargs:
必传参数
	mch_order_no
	total_fee
	fee_type
	channel
	sub_openid
	channel_sub_appid
选传参数
	redirect_url
	notify_url
	paypage_title
	product
	operator_id
:return:
*/
func (client Client) MiniproPay(mchOrderNo, feeType, channel, subOpenid, channelSubAppId string, totalFee int) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
		"total_fee": {strconv.Itoa(totalFee)},
		"fee_type": {feeType},
		"channel": {channel},
		"sub_openid": {subOpenid},
		"channel_sub_appid": {channelSubAppId},
	}
	return KsherPost(PayDomain+"/mini_program_pay", postValue, client.PrivateKey, client.PublicKey)
}
/*
app支付
:param kwargs:
必传参数
	mch_order_no
	total_fee
	fee_type
	channel
	sub_openid
	channel_sub_appid
选传参数
	redirect_url
	notify_url
	paypage_title
	product
	attach
	operator_id
	refer_url 仅当channel为alipay时需要
:return:
*/
func (client Client) AppPay(mchOrderNo, feeType, channel, subOpenid, channelSubAppId string, totalFee int) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
		"total_fee": {strconv.Itoa(totalFee)},
		"fee_type": {feeType},
		"channel": {channel},
		"sub_openid": {subOpenid},
		"channel_sub_appid": {channelSubAppId},
	}
	return KsherPost(PayDomain+"/app_pay", postValue, client.PrivateKey, client.PublicKey)
}
/*
H5支付，仅支持channel=alipay
:param kwargs:
必传参数
	mch_order_no
	total_fee
	fee_type
	channel
选传参数
	redirect_url
	notify_url
	paypage_title
	product
	attach
	operator_id
	device_id
	refer_url
:return:
*/
func (client Client) WapPay(mchOrderNo, feeType, channel string, totalFee int) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
		"total_fee": {strconv.Itoa(totalFee)},
		"fee_type": {feeType},
		"channel": {channel},
	}
	return KsherPost(PayDomain+"/wap_pay", postValue, client.PrivateKey, client.PublicKey)
}
/*
PC网站支付，仅支持channel=alipay
:param kwargs:
必传参数
	mch_order_no
	total_fee
	fee_type
	channel
选传参数
	redirect_url
	notify_url
	paypage_title
	product
	attach
	operator_id
	device_id
	refer_url
:return:
*/
func (client Client) WepPay(mchOrderNo, feeType, channel string, totalFee int) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
		"total_fee": {strconv.Itoa(totalFee)},
		"fee_type": {feeType},
		"channel": {channel},
	}
	return KsherPost(PayDomain+"/wap_pay", postValue, client.PrivateKey, client.PublicKey)
}
/*
订单查询
:param kwargs:
必传参数
	mch_order_no、ksher_order_no、channel_order_no三选一
:return:
*/
func (client Client) OrderQuery(mchOrderNo string) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
	}
	return KsherPost(PayDomain+"/order_query", postValue, client.PrivateKey, client.PublicKey)
}
/*
订单关闭
:param kwargs:
必传参数
	mch_order_no、ksher_order_no、channel_order_no三选一
选传参数
	operator_id
:return:
*/
func (client Client) OrderClose(mchOrderNo string) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
	}
	return KsherPost(PayDomain+"/order_close", postValue, client.PrivateKey, client.PublicKey)
}
/*
订单撤销
:param kwargs:
必传参数
	mch_order_no、ksher_order_no、channel_order_no三选一
选传参数
	operator_id
:return:
*/
func (client Client) OrderReverse(mchOrderNo string) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
	}
	return KsherPost(PayDomain+"/order_reverse", postValue, client.PrivateKey, client.PublicKey)
}
/*
订单退款
:param kwargs:
必传参数
	total_fee
	fee_type
	refund_fee
	mch_refund_no
	mch_order_no、ksher_order_no、channel_order_no三选一
选传参数
	operator_id
:return:
*/
func (client Client) OrderRefund(mchRefundNo, feeType, mchOrderNo string, refundFee, totalFee int) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
		"mch_refund_no": {mchRefundNo},
		"fee_type": {feeType},
		"refund_fee": {strconv.Itoa(refundFee)},
		"total_fee": { strconv.Itoa(totalFee)},
	}
	return KsherPost(PayDomain+"/order_refund", postValue, client.PrivateKey, client.PublicKey)
}
/*
退款查询
:param kwargs:
	必传参数
		mch_refund_no、ksher_refund_no、channel_refund_no三选一
		mch_order_no、ksher_order_no、channel_order_no三选一
*/
func (client Client) RefundQuery(mchRefundNo, mchOrderNo string) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"mch_order_no": {mchOrderNo},
		"mch_refund_no": {mchRefundNo},
	}
	return KsherPost(PayDomain+"/refund_query", postValue, client.PrivateKey, client.PublicKey)
}
/*
汇率查询
:param kwargs:
	必传参数
		channel
		fee_type
		date
:return:
*/
func (client Client) RateQuery(channel, feeType, date string) (response KsherResp, err error) {
	postValue := url.Values{
		"appid": {client.AppId},
		"nonce_str": {GetNonceStr(4)},
		"time_stamp": {GetTimeStamp()},
		"channel": {channel},
		"fee_type": {feeType},
		"date": {date},
	}
	return KsherPost(PayDomain+"/rate_query", postValue, client.PrivateKey, client.PublicKey)
}