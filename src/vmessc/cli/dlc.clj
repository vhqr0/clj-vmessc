(ns vmessc.cli.dlc
  (:require [clojure.string :as str]
            [vmessc.sys :as sys]
            [vmessc.cli.core :as core]))

;; Domain List Comunity

;; origin: https://github.com/v2fly/domain-list-community
;; my fork: https://github.com/vhqr0/domain-list-community

(def ^:dynamic *remote-repo*
  "Remote git repo of DLC."
  "https://github.com/vhqr0/domain-list-community")

(def ^:dynamic *local-repo*
  "Local git repo if DLC."
  "conf/dlc")

(defn clone-command
  "DLC repo clone command."
  []
  (str "git clone " *remote-repo* " " *local-repo*))

(defn pull-command
  "DLC repo pull ocmmand."
  []
  (str "cd " *local-repo* " && git pull"))

(defn clone-or-pull-command
  "DLC repo clone or pull command."
  []
  (if (sys/file-exists? *local-repo*)
    (pull-command)
    (clone-command)))

^:rct/test
(comment
  (clone-command)
  ;; =>
  "git clone https://github.com/vhqr0/domain-list-community conf/dlc"
  (pull-command)
  ;; =>
  "cd conf/dlc && git pull")

(defn clone-or-pull
  "Clone or pull DLC repo."
  []
  (let [command (clone-or-pull-command)]
    (core/log {:level :info :type :cli/sh :app :dlc :command command})
    (sys/sh command)))

(defn data-path
  "Get data path."
  [name]
  (str *local-repo* "/data/" name))

^:rct/test
(comment
  (data-path "cn")
  ;; =>
  "conf/dlc/data/cn")

(def line-re
  "DLC line regexp."
  #"^((\w+):)?([^\s\t#]+)( @([^\s\t#]+))?")

^:rct/test
(comment
  (re-matches line-re "a.baidu.com")
  ;; =>
  ["a.baidu.com" nil nil "a.baidu.com" nil nil]
  (re-matches line-re "a.baidu.com @ads")
  ;; =>
  ["a.baidu.com @ads" nil nil "a.baidu.com" " @ads" "ads"]
  (re-matches line-re "include:geolocation-cn")
  ;; =>
  ["include:geolocation-cn" "include:" "include" "geolocation-cn" nil nil])

(def dlc-tag->tag
  "Mapping from DLC tags to internal tags."
  {"ads" :block "cn" :direct "!cn" :proxy})

(defn tags-seq
  "Return seq of tags."
  [name default-tag]
  (->> (slurp (data-path name))
       str/split-lines
       (mapcat
        (fn [line]
          (let [line (-> (first (str/split line #"#" 2)) str/trim)]
            (when-not (str/blank? line)
              (if-let [matches (re-matches line-re line)]
                (case (or (get matches 2) "domain")
                  ("domain" "full") (let [domain (get matches 3)
                                          tag (-> (get matches 5) (dlc-tag->tag default-tag))]
                                      [[domain tag]])
                  "include" (let [name (get matches 3)]
                              (tags-seq name default-tag))
                  ;; we don't support regexp yet
                  "regexp" nil
                  (core/log {:level :debug :type :cli/unknown-command :app :dlc :content-type :dlc/line :content line}))
                (core/log {:level :debug :type :cli/parse-error :app :dlc :connent-type :dlc/line :content line}))))))))

(defn gen-tags
  "Generate tags edn file."
  []
  (let [tags (vec (concat
                   (tags-seq "cn" :direct)
                   (tags-seq "geolocation-!cn" :proxy)))]
    (spit core/*tags-path* tags)))
