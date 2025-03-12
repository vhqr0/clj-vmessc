(ns vmessc.core
  (:require [clojure.string :as str]
            [clojure.edn :as edn]
            [clojure.core.async :as a]
            [clj-bytes.core :as b]
            [clj-proxy.core :as prx]
            clj-proxy.net
            clj-proxy.socks5
            [vmessc.vmess :as vmess])
  (:import [java.io Closeable]
           [java.util Date]
           [java.text SimpleDateFormat]))

;;; utils

(def ^:dynamic *log-fn* prn)

(defn now
  "Get current date inst."
  []
  (Date.))

(def ^:dynamic ^SimpleDateFormat *date-formatter*
  "Inst formatter."
  (SimpleDateFormat. "yyyy-MM-dd-HH:mm:ss"))

(defn inst-fmt
  "Format inst."
  ([]
   (inst-fmt (now)))
  ([^Date i]
   (-> *date-formatter* (.format i))))

(defn with-conf-prefix
  [name]
  (str "conf/" name))

(defn with-bak-prefix
  [name]
  (with-conf-prefix (str "bak/" (inst-fmt) \. name)))

(comment
  (inst-fmt)
  (with-bak-prefix "tags.edn"))

(defn conf-spit
  [name data]
  (spit (with-bak-prefix name) data)
  (spit (with-conf-prefix name) data))

(defn conf-slurp
  [name]
  (slurp (with-conf-prefix name)))

(def default-opts
  {:test-server-addr ["www.google.com" 80]
   :test-timeout-ms 10000
   :server-port 10086
   :server-default-tag :direct
   :server-log-levels #{:info :error}})

(defn opts-load
  []
  (merge default-opts (edn/read-string (conf-slurp "opts.edn"))))

;;; tags

(defn tags-load
  []
  (edn/read-string (conf-slurp "tags.edn")))

;;;; dlc

;; domain list community
;; origin: https://github.com/v2fly/domain-list-community
;; my fork: https://github.com/vhqr0/domain-list-community

(defn dlc-data-path
  [name]
  (str "domain-list-community/data/" name))

(defn dlc-data-slurp
  [name]
  (conf-slurp (dlc-data-path name)))

(comment
  (dlc-data-path "cn") ; => "domain-list-community/data/cn"
  )

(def dlc-line-re
  #"^((\w+):)?([^\s\t#]+)( @([^\s\t#]+))?")

(comment
  (re-matches dlc-line-re "a.baidu.com") ; => ["a.baidu.com" nil nil "a.baidu.com" nil nil]
  (re-matches dlc-line-re "a.baidu.com @ads") ; => ["a.baidu.com @ads" nil nil "a.baidu.com" " @ads" "ads"]
  (re-matches dlc-line-re "include:geolocation-cn") ; => ["include:geolocation-cn" "include:" "include" "geolocation-cn" nil nil]
  )

(def dlc-tag-map
  {"ads" :block "cn" :direct "!cn" :proxy})

(defn dlc-tags-seq
  "Return seq of tags."
  [name default-tag]
  (->> (dlc-data-slurp name)
       str/split-lines
       (mapcat
        (fn [line]
          (let [line (-> (first (str/split line #"#" 2)) str/trim)]
            (when-not (str/blank? line)
              (if-let [matches (re-matches dlc-line-re line)]
                (case (or (get matches 2) "domain")
                  ("domain" "full") (let [domain (get matches 3)
                                          tag (get matches 5)
                                          tag (get dlc-tag-map tag default-tag)]
                                      [[domain tag]])
                  "include" (let [name (get matches 3)]
                              (dlc-tags-seq name default-tag))
                  ;; we don't support regexp yet
                  "regexp" nil
                  (*log-fn* {:type :dlc/parse-error :line line}))
                (*log-fn* {:type :dlc/parse-error :line line}))))))))

(defn dlc-tags-gen
  []
  (->> (concat
        (dlc-tags-seq "cn" :direct)
        (dlc-tags-seq "geolocation-!cn" :proxy))
       vec
       (conf-spit "tags.edn")))

;;; sub

(defn sub->edn
  [s]
  (->> (vmess/v2rayn-sub->urls s)
       (filter #(str/starts-with? % "vmess://"))
       (mapv
        (fn [url]
          (try
            (-> url vmess/vmess-url->json vmess/vmess-json->edn)
            (catch Exception e
              (*log-fn* {:type :sub/parse-error :url url :ex e})))))))

(defn sub-fetch
  []
  (->> (conf-slurp "sub.url") str/trim slurp (conf-spit "sub.txt")))

(defn sub-gen
  []
  (->> (conf-slurp "sub.txt") sub->edn vec (conf-spit "sub.edn")))

(defn sub-load
  []
  (edn/read-string (conf-slurp "sub.edn")))

(defn int->str2
  [i]
  (let [s (str i)]
    (if-not (= (count s) 1) s (str \space s))))

(defn sub-list-1
  [i {:keys [selected? name delay] :or {delay :timeout} :as edn}]
  (println (int->str2 i) (if selected? "[x]" "[ ]") name delay (select-keys edn [:addr :net :tls?])))

(defn sub-list
  []
  (doseq [[i edn] (->> (sub-load) (map-indexed vector))]
    (sub-list-1 i edn)))

(defn sub-select
  [idxs]
  (->> (sub-load) (map-indexed #(assoc %2 :selected? (contains? idxs %1))) vec (conf-spit "sub.edn")))

;;;; test

(defn sub-test-connect
  [{:keys [name uuid] :as edn} [host _ :as addr]]
  (let [opts (vmess/vmess-edn->opts edn)
        context {:log-fn *log-fn* :uuid uuid :addr addr}]
    (a/go
      (prx/log context {:level :debug :type :test-connect :via name})
      (if-let [{[ich och] :server} (a/<! (prx/connect context opts))]
        (if (a/>! och (b/of-str (str "GET / HTTP/1.1\r\nHost: " host "\r\n\r\n")))
          (if (some? (a/<! ich))
            (do
              (a/close! ich)
              (a/close! och)
              (prx/log context {:level :debug :type :test-connect-ok :via name})
              :ok)
            (prx/log context {:level :error :type :test-connect-error :reason :test-connect/read :via name}))
          (prx/log context {:level :error :type :test-connect-error :reason :test-connect/write :via name}))
        (prx/log context {:level :error :type :test-connect-error :reason :test-connect/connect :via name})))))

(defn sub-test-1
  [edn addr timeout-ms]
  (let [start-inst (now)]
    (a/go
      (let [connect-ch (sub-test-connect edn addr)
            timeout-ch (a/timeout timeout-ms)]
        (a/alt!
          connect-ch ([_] (- (inst-ms (now)) (inst-ms start-inst)))
          timeout-ch ([_] :timeout))))))

(defn sub-test
  []
  (let [{:keys [test-server-addr test-timeout-ms]} (opts-load)
        sub-atom (atom (sub-load))]
    (doseq [[i edn] (->> @sub-atom (map-indexed vector))]
      (a/go
        (let [delay (or (a/<! (sub-test-1 edn test-server-addr test-timeout-ms)) :timeout)]
          (swap! sub-atom update i merge {:selected? (not= delay :timeout) :delay delay}))))
    (Thread/sleep ^long (+ test-timeout-ms 1000))
    (let [s @sub-atom]
      (*log-fn* {:type :test/finish})
      (->> s (conf-spit "sub.edn")))))

;;; server

(defn server-log
  [msg opts]
  (let [{:keys [levels prefer-keys]
         :or {levels #{:debug :info :error}
              prefer-keys [:uuid :level :type :addr]}}
        opts]
    (when (contains? levels (:level msg))
      (let [timestamp (now)
            data (->> prefer-keys
                      (reduce
                       (fn [data k]
                         (let [v (get msg k)]
                           (cond-> data (some? v) (conj v))))
                       [timestamp]))
            msg (->> prefer-keys
                     (reduce dissoc msg)
                     (remove #(nil? (val %)))
                     (into {}))
            data (cond-> data
                   (seq msg) (conj msg))]
        (prn data)))))

(defn start-server-log
  [ch opts]
  (a/go-loop []
    (when-let [msg (a/<! ch)]
      (server-log msg opts)
      (recur))))

(defn server-context-load
  ([]
   (let [opts (opts-load)
         tag-map (->> (tags-load) (into {}))
         sub-opts (->> (sub-load) (filter :selected?) (mapv vmess/vmess-edn->opts))]
     (server-context-load opts tag-map sub-opts)))
  ([opts tag-map sub-opts]
   {:pre [(seq sub-opts)]}
   (let [{:keys [server-port server-default-tag server-log-levels]} opts]
     {:log-opts {:levels server-log-levels}
      :net-server-opts {:type :tcp :port server-port}
      :proxy-server-opts {:type :socks5}
      :connect-opts {:type :tag-dispatch
                     :name "main"
                     :tag-map tag-map
                     :default-tag server-default-tag
                     :sub-opts {:direct {:type :direct :name "direct"}
                                :block {:type :block :name "block"}
                                :proxy {:type :rand-dispatch :name "proxy" :sub-opts sub-opts}}}})))

(defn start-server
  ([]
   (start-server (server-context-load)))
  ([context]
   (let [{:keys [log-opts]} context
         log-ch (a/chan 1024)]
     (start-server-log log-ch log-opts)
     [log-ch (a/<!! (prx/start-server (assoc context :log-fn #(a/put! log-ch %))))])))

(defn close-server
  [[log-ch server]]
  (a/close! log-ch)
  (.close ^Closeable server))
