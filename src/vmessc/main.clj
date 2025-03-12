(ns vmessc.main
  (:require [vmessc.core :as core])
  (:gen-class))

(defn -main [& _]
  (core/start-server))
