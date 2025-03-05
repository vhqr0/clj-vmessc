(ns vmessc.cli.svc
  (:require [clojure.edn :as edn]
            [vmessc.sys :as sys]
            [vmessc.server :as server]
            [vmessc.vmess :as vmess]
            [vmessc.cli.core :as core]))

(defn tag-map
  []
  (let [tags (concat
              (-> core/*tags-path* slurp edn/read-string)
              (when (sys/file-exists? core/*custom-tags-path*)
                (-> core/*custom-tags-path* slurp read-string)))]
    (into {} tags)))

(defn vmess-param->vmess-opts
  [{:keys [name uuid net]}]
  (let [id (vmess/->id uuid)]
    {:name name
     :type :proxy
     :proxy-opts {:type :vmess :id id :net-opts net}}))

(comment
  (require '[clojure.core.async :as a])
  (require '[clj-bytes.core :as b])
  (def param {:name "vmess-test"
              :uuid "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297"
              :net {:type :tcp :host "localhost" :port 10086}})
  (def opts (vmess-param->vmess-opts param))
  (def buffer (b/of-str "GET / HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n"))
  (def addr ["www.baidu.com" 80])
  (def info {:addr addr :buffer buffer})
  (a/go
    (if-let [[_path ch] (server/connect info opts)]
      (let [[ich och] (a/<! ch)]
        (if (a/>! och buffer)
          (if-let [b (a/<! ich)]
            (println (b/str b))
            (println "read failed"))
          (println "write failed")))
      (println "proxy connect failed"))))
