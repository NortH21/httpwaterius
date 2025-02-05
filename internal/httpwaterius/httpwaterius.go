/*
Copyright (c) grffio.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/

package httpwaterius

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"
	"io/ioutil"
	"bytes"

	"github.com/i-core/rlog"
	"go.uber.org/zap"
)

// ServiceConfig is a httpwaterius's configuration.
type ServiceConfig struct {
	Devices  []string `envconfig:"devices" default:"Bathroom" desc:"a unique devices names that declared in 'key' field in waterius devices (<Name1>,<Name2>)"`
	Username string   `envconfig:"username" desc:"a username for basic authenticaion"`
	Password string   `envconfig:"password" desc:"a password for basic authenticaion"`
}

// Handler is an HTTP handler that receives data over HTTP from waterius devices and displays them in simple Web UI.
type Handler struct {
	ServiceConfig
	indexFile string
}

var devicesData map[string]Data
var devicesDataMutex sync.RWMutex

// NewHandler returns a new instance of Handler.
func NewHandler(f string, s ServiceConfig) (*Handler, error) {
	devicesData = make(map[string]Data)
	return &Handler{ServiceConfig: s, indexFile: f}, nil
}

// AddRoutes registers all required routes for the package httpwaterius.
func (h *Handler) AddRoutes(apply func(m, p string, h http.Handler, mws ...func(http.Handler) http.Handler)) {
	apply(http.MethodPost, "data", newDataHandler(h.Devices))
	apply(http.MethodGet, "", newClientHandler(h.indexFile), basicAuth(h.Username, h.Password))
}

// Data is a data received in an HTTP request for rendering in index.html.
type Data struct {
	Delta0              float64 `json:"delta0"`
	Delta1              float64 `json:"delta1"`
	Ch0                 float64 `json:"ch0"`
	Ch1                 float64 `json:"ch1"`
	Ch0Start            float64 `json:"ch0_start"`
	Ch1Start            float64 `json:"ch1_start"`
	Imp0                int     `json:"imp0"`
	Imp1                int     `json:"imp1"`
	F0                  int     `json:"f0"`
	F1                  int     `json:"f1"`
	Adc0                int     `json:"adc0"`
	Adc1                int     `json:"adc1"`
	Serial0             string  `json:"serial0"`
	Serial1             string  `json:"serial1"`
	Ctype0              int     `json:"ctype0"`
	Ctype1              int     `json:"ctype1"`
	Cname0              int     `json:"cname0"`
	Cname1              int     `json:"cname1"`
	DataType0           int     `json:"data_type0"`
	DataType1           int     `json:"data_type1"`
	Voltage             float64 `json:"voltage"`
	VoltageLow          bool    `json:"voltage_low"`
	VoltageDiff         float64 `json:"voltage_diff"`
	Battery             int     `json:"battery"`
	Channel             int     `json:"channel"`
	WifiPhyMode         string  `json:"wifi_phy_mode"`
	WifiPhyModeS        string  `json:"wifi_phy_mode_s"`
	WifiConnectErrors   int     `json:"wifi_connect_errors"`
	WifiConnectAttempt  int     `json:"wifi_connect_attempt"`
	RouterMac           string  `json:"router_mac"`
	Rssi                int     `json:"rssi"`
	Mac                 string  `json:"mac"`
	IP                  string  `json:"ip"`
	Dhcp                bool    `json:"dhcp"`
	Version             int     `json:"version"`
	VersionESP          string  `json:"version_esp"`
	EspID               int     `json:"esp_id"`
	FlashID             int     `json:"flash_id"`
	Freemem             int     `json:"freemem"`
	Timestamp           string  `json:"timestamp"`
	Waketime            int     `json:"waketime"`
	PeriodMinTuned      int     `json:"period_min_tuned"`
	PeriodMin           int     `json:"period_min"`
	Setuptime           int     `json:"setuptime"`
	Boot                int     `json:"boot"`
	Resets              int     `json:"resets"`
	Mode                int     `json:"mode"`
	SetupFinished       int     `json:"setup_finished"`
	SetupStarted        int     `json:"setup_started"`
	NtpErrors           int     `json:"ntp_errors"`
	Key                 string  `json:"key"`
	Email               string  `json:"email"`
	Mqtt                bool    `json:"mqtt"`
	Ha                  bool    `json:"ha"`
	Http                bool    `json:"http"`
	Company             string  `json:"company"`
	Place               string  `json:"place"`
	LastCheck           string  // Внутреннее поле, не из JSON
	PowerColor          string  // Внутреннее поле, не из JSON
}

/* {"delta0":0,"delta1":0,"ch0":0.219999999,"ch1":1.190000057,"ch0_start":0,"ch1_start":0.99000001,
"imp0":25,"imp1":25,"f0":10,"f1":10,"adc0":106,"adc1":106,
"serial0":"230525823","serial1":"230529207","ctype0":0,"ctype1":0,"cname0":1,"cname1":0,
"data_type0":1,"data_type1":0,"voltage":3.13,"voltage_low":false,"voltage_diff":0.007,
"battery":90,"channel":2,"wifi_phy_mode":"N","wifi_phy_mode_s":"0","wifi_connect_errors":0,
"wifi_connect_attempt":2,"router_mac":"50:FF:20:00:00:00","rssi":-53,"mac":"EC:64:C9:DA:51:2D",
"ip":"192.168.1.134","dhcp":true,"version":32,"version_esp":"1.1.7","esp_id":14307629,"flash_id":1335390,
"freemem":39712,"timestamp":"2025-02-02T21:23:51+0000","waketime":5685,"period_min_tuned":1440,
"period_min":1440,"setuptime":35210,"boot":1,"resets":3,"mode":3,"setup_finished":5,"setup_started":5,
"ntp_errors":0,"key":"51DCFCEA7459747E2FDE81F10D03A0C3","email":"example@example.com",
"mqtt":false,"ha":false,"http":true,"company":"","place":"Bathroom"}
*/

func newDataHandler(devices []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := rlog.FromContext(r.Context()).Sugar()

		// Логируем тело запроса перед обработкой
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintln("Failed to read request body")
			http.Error(w, msg, http.StatusInternalServerError)
			log.Debugf(msg, zap.Error(err))
			return
		}
		log.Infof("Received POST request body: %s", string(body))

		// Возвращаем тело запроса в исходное состояние для дальнейшей обработки
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		if r.Body == http.NoBody {
			msg := fmt.Sprintln("No body")
			http.Error(w, msg, http.StatusBadRequest)
			log.Debug(msg)
			return
		}

		var data Data
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			msg := fmt.Sprintln("Invalid body")
			http.Error(w, msg, http.StatusBadRequest)
			log.Debugf(msg, zap.Error(err))
			return
		}

		log.Info(data)
		if data.Key == "" {
			msg := fmt.Sprintln("Missing required field: key")
			http.Error(w, msg, http.StatusBadRequest)
			log.Debug(msg)
			return
		}

		// Проверяем, что Ch0 и Ch1 не равны нулю
		if data.Ch0 == 0 || data.Ch1 == 0 {
			msg := fmt.Sprintln("Missing required fields: ch0 or ch1")
			http.Error(w, msg, http.StatusBadRequest)
			log.Debug(msg)
			return
		}

		var deviceSupported bool
		for _, d := range devices {
			if d == data.Key {
				deviceSupported = true
				break
			}
		}
		if !deviceSupported {
			msg := fmt.Sprintf("Unsupported device: %s", data.Key)
			http.Error(w, msg, http.StatusBadRequest)
			log.Debug(msg)
			return
		}

		go func(d Data) {
			pwColor := "mediumseagreen"
			if d.VoltageLow { // Теперь VoltageLow — это bool
				pwColor = "orange"
			}
			currentTime := time.Now().Format("15:04 02/01/06")
			devicesDataMutex.Lock()
			defer devicesDataMutex.Unlock()
			devicesData[d.Key] = Data{
				Delta0:              d.Delta0,
				Delta1:              d.Delta1,
				Ch0:                 d.Ch0,
				Ch1:                 d.Ch1,
				Ch0Start:            d.Ch0Start,
				Ch1Start:            d.Ch1Start,
				Imp0:                d.Imp0,
				Imp1:                d.Imp1,
				F0:                  d.F0,
				F1:                  d.F1,
				Adc0:                d.Adc0,
				Adc1:                d.Adc1,
				Serial0:             d.Serial0,
				Serial1:             d.Serial1,
				Ctype0:              d.Ctype0,
				Ctype1:              d.Ctype1,
				Cname0:              d.Cname0,
				Cname1:              d.Cname1,
				DataType0:           d.DataType0,
				DataType1:           d.DataType1,
				Voltage:             d.Voltage,
				VoltageLow:          d.VoltageLow,
				VoltageDiff:         d.VoltageDiff,
				Battery:             d.Battery,
				Channel:             d.Channel,
				WifiPhyMode:         d.WifiPhyMode,
				WifiPhyModeS:        d.WifiPhyModeS,
				WifiConnectErrors:   d.WifiConnectErrors,
				WifiConnectAttempt:  d.WifiConnectAttempt,
				RouterMac:           d.RouterMac,
				Rssi:                d.Rssi,
				Mac:                 d.Mac,
				IP:                  d.IP,
				Dhcp:                d.Dhcp,
				Version:             d.Version,
				VersionESP:          d.VersionESP,
				EspID:               d.EspID,
				FlashID:             d.FlashID,
				Freemem:             d.Freemem,
				Timestamp:           d.Timestamp,
				Waketime:            d.Waketime,
				PeriodMinTuned:      d.PeriodMinTuned,
				PeriodMin:           d.PeriodMin,
				Setuptime:           d.Setuptime,
				Boot:                d.Boot,
				Resets:              d.Resets,
				Mode:                d.Mode,
				SetupFinished:       d.SetupFinished,
				SetupStarted:        d.SetupStarted,
				NtpErrors:           d.NtpErrors,
				Key:                 d.Key,
				Email:               d.Email,
				Mqtt:                d.Mqtt,
				Ha:                  d.Ha,
				Http:                d.Http,
				Company:             d.Company,
				Place:               d.Place,
				LastCheck:           currentTime,
				PowerColor:          pwColor,
			}
		}(data)
	}
}

func newClientHandler(f string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := rlog.FromContext(r.Context()).Sugar()

		tmpl, err := template.ParseFiles(f)
		if err != nil {
			msg := fmt.Sprintln("Unable to parse template file")
			http.Error(w, msg, http.StatusInternalServerError)
			log.Debugf(msg, zap.Error(err))
		}
		tmpl.Execute(w, devicesData)
	}
}

func basicAuth(user, password string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if user != "" {
				if u, p, ok := r.BasicAuth(); !(ok && u == user && p == password) {
					w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
					http.Error(w, "", http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
