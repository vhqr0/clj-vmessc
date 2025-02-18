(ns vmessc.sys
  (:require [clojure.java.shell :as shell])
  (:import [java.util Date]
           [java.text SimpleDateFormat]
           [java.io File]))

;;; shell

(defn sh
  "Execute shell command."
  [command]
  (shell/sh "sh" "-c" command))

;;; date

(defn now
  "Get current date inst."
  []
  (Date.))

(def ^:dynamic *date-formatter*
  "Inst formatter."
  (SimpleDateFormat. "yyyy-MM-dd-HH:mm:ss"))

(defn inst-fmt
  "Format inst."
  [i]
  (-> *date-formatter* (.format i)))

(comment
  (inst-fmt (now)))

;;; file

(defn file-exists?
  "Check if file is exists."
  [path]
  (-> (File. path) .exists))

(comment
  (file-exists? "."))
