(ns vmessc.cli.core
  (:require [vmessc.sys :as sys]
            [vmessc.server :as server]
            vmessc.socks5
            vmessc.vmess))

(def ^:dynamic *log-opts*
  "CLI default log opts."
  {:type :console})

(defn log
  "CLI default log fn."
  [msg]
  (server/log msg *log-opts*))

(def ^:dynamic *bak-path*
  "Bakup directory path."
  "conf/bak")

(def ^:dynamic *tags-path*
  "Tags edn path."
  "conf/tags.edn")

(defn bak-prefix
  []
  (let [now (-> (sys/now) sys/inst-fmt)]
    (str *bak-path* "/" now ".")))

(comment
  (bak-prefix))
