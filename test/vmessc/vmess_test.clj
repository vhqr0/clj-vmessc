(ns vmessc.vmess-test
  (:require [clojure.core.async :as a]
            [clj-bytes.core :as b]
            [clj-proxy.core :as prx]
            clj-proxy.net
            [vmessc.vmess :as vmess]))

;; vmess test config: https://github.com/v2fly/v2ray-core/blob/master/release/config/vpoint_vmess_freedom.json

(def vmess-edn
  {:name "vmess-test"
   :uuid "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297"
   :net :tcp
   :addr ["localhost" 10086]})

(def vmess-opts
  (vmess/vmess-edn->opts vmess-edn))

(defn http-request
  [host]
  (let [context {:addr [host 80] :log-fn prn}]
    (a/go
      (if-let [{[ich och] :server} (a/<! (prx/connect context vmess-opts))]
        (if (a/>! och (b/of-str (str "GET / HTTP/1.1\r\nHost: " host "\r\n\r\n")))
          (if-let [b (a/<! ich)]
            (println (b/str b))
            (println "read error: " host))
          (println "write error:" host))
        (println "connect error:" host)))))

(comment
  (http-request "www.baidu.com"))
