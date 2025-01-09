// Copyright 2020 Ohio Supercomputer Center
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/version"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	appName            = "job-pod-reaper"
	lifetimeAnnotation = "pod.kubernetes.io/lifetime"
	metricsPath        = "/metrics"
	metricsNamespace   = "job_pod_reaper"
)

var (
	runOnce         = kingpin.Flag("run-once", "Set application to run once then exit, ie executed with cron").Default("false").Envar("RUN_ONCE").Bool()
	reapMax         = kingpin.Flag("reap-max", "Maximum Pods to reap in each run, set to 0 to disable this limit").Default("30").Envar("REAP_MAX").Int()
	reapInterval    = kingpin.Flag("reap-interval", "Duration between repear runs").Default("60s").Envar("REAP_INTERLVAL").Duration()
	reapNamespaces  = kingpin.Flag("reap-namespaces", "Namespaces to reap, ignored if --namespace-labels is set").Default("all").Envar("REAP_NAMESPACES").String()
	namespaceLabels = kingpin.Flag("namespace-labels", "Labels to use when filtering namespaces, causes --namespace-labels to be ignored").Default("").Envar("NAMESPACE_LABELS").String()
	objectLabels    = kingpin.Flag("object-labels", "Labels to use when filtering objects").Default("").Envar("OBJECT_LABELS").String()
	jobLabel        = kingpin.Flag("job-label", "Label to associate pod job with other objects").Default("job").Envar("JOB_LABEL").String()
	kubeconfig      = kingpin.Flag("kubeconfig", "Path to kubeconfig when running outside Kubernetes cluster").Default("").Envar("KUBECONFIG").String()
	listenAddress   = kingpin.Flag("listen-address", "Address to listen for HTTP requests").Default(":8080").Envar("LISTEN_ADDRESS").String()
	processMetrics  = kingpin.Flag("process-metrics", "Collect metrics about running process such as CPU and memory and Go stats").Default("true").Envar("PROCESS_METRICS").Bool()
	logLevel        = kingpin.Flag("log-level", "Log level, One of: [debug, info, warn, error]").Default("info").Envar("LOG_LEVEL").Enum(promslog.LevelFlagOptions...)
	logFormat       = kingpin.Flag("log-format", "Log format, One of: [logfmt, json]").Default("logfmt").Envar("LOG_FORMAT").Enum(promslog.FormatFlagOptions...)
	timeNow         = time.Now
	metricBuildInfo = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "build_info",
		Help:      "Build information",
		ConstLabels: prometheus.Labels{
			"version":   version.Version,
			"revision":  version.Revision,
			"branch":    version.Branch,
			"builddate": version.BuildDate,
			"goversion": version.GoVersion,
		},
	})
	metricReapedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "reaped_total",
			Help:      "Total number of object types reaped",
		},
		[]string{"type"},
	)
	metricError = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "error",
		Help:      "Indicates an error was encountered",
	})
	metricErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "errors_total",
		Help:      "Total number of errors",
	})
	metricDuration = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "run_duration_seconds",
		Help:      "Last runtime duration in seconds",
	})
)

type podJob struct {
	jobID     string
	podName   string
	namespace string
}

type jobObject struct {
	objectType string
	jobID      string
	name       string
	namespace  string
}

func init() {
	metricBuildInfo.Set(1)
	metricReapedTotal.WithLabelValues("pod")
	metricReapedTotal.WithLabelValues("service")
	metricReapedTotal.WithLabelValues("configmap")
	metricReapedTotal.WithLabelValues("secret")
}

func main() {
	kingpin.Version(version.Print(appName))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	level := &promslog.AllowedLevel{}
	_ = level.Set(*logLevel)
	format := &promslog.AllowedFormat{}
	_ = format.Set(*logFormat)
	promslogConfig := &promslog.Config{
		Level:  level,
		Format: format,
	}
	logger := promslog.New(promslogConfig)

	var config *rest.Config
	var err error

	if *kubeconfig == "" {
		logger.Info("Loading in cluster kubeconfig", "kubeconfig", *kubeconfig)
		config, err = rest.InClusterConfig()
	} else {
		logger.Info("Loading kubeconfig", "kubeconfig", *kubeconfig)
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	}
	if err != nil {
		logger.Error("Error loading kubeconfig", "err", err)
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Error("Unable to generate Clientset", "err", err)
		os.Exit(1)
	}

	logger.Info(fmt.Sprintf("Starting %s", appName), "version", version.Info())
	logger.Info("Build context", "build_context", version.BuildContext())

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
	             <head><title>job-pod-reaper</title></head>
	             <body>
	             <h1>job-pod-reaper</h1>
	             <p><a href='/metrics'>Metrics</a></p>
	             </body>
	             </html>`))
	})
	http.Handle(metricsPath, promhttp.HandlerFor(metricGathers(), promhttp.HandlerOpts{}))

	go func() {
		if err := http.ListenAndServe(*listenAddress, nil); err != nil {
			logger.Error("Error starting HTTP server", "err", err)
			os.Exit(1)
		}
	}()

	for {
		var errNum int
		start := timeNow()
		err = run(clientset, logger)
		metricDuration.Set(time.Since(start).Seconds())
		if err != nil {
			errNum = 1
		} else {
			errNum = 0
		}
		metricError.Set(float64(errNum))
		if *runOnce {
			os.Exit(errNum)
		} else {
			logger.Debug("Sleeping for interval", "interval", fmt.Sprintf("%.0f", (*reapInterval).Seconds()))
			time.Sleep(*reapInterval)
		}
	}
}

func run(clientset kubernetes.Interface, logger *slog.Logger) error {
	namespaces, err := getNamespaces(clientset, logger)
	if err != nil {
		logger.Error("Error getting namespaces", "err", err)
		return err
	}
	jobs, jobIDs, err := getJobs(clientset, namespaces, logger)
	if err != nil {
		logger.Error("Error getting jods", "err", err)
		return err
	}
	orphanedObjects, err := getOrphanedJobObjects(clientset, jobs, jobIDs, namespaces, logger)
	if err != nil {
		logger.Error("Error getting orphaned objects", "err", err)
	}
	jobObjects, err := getJobObjects(clientset, jobs, logger)
	if err != nil {
		logger.Error("Error getting job objects", "err", err)
		return err
	}
	jobObjects = append(jobObjects, orphanedObjects...)
	errCount := reap(clientset, jobObjects, logger)
	if errCount > 0 {
		err := fmt.Errorf("%d errors encountered during reap", errCount)
		logger.Error(err.Error())
		return err
	}
	return nil
}

func getNamespaces(clientset kubernetes.Interface, logger *slog.Logger) ([]string, error) {
	var namespaces []string
	namespaces = strings.Split(*reapNamespaces, ",")
	if len(namespaces) == 1 && strings.ToLower(namespaces[0]) == "all" {
		namespaces = []string{metav1.NamespaceAll}
	}
	if *namespaceLabels != "" {
		namespaces = nil
		nsLabels := strings.Split(*namespaceLabels, ",")
		for _, label := range nsLabels {
			nsListOptions := metav1.ListOptions{
				LabelSelector: label,
			}
			logger.Debug("Getting namespaces with label", "label", label)
			ns, err := clientset.CoreV1().Namespaces().List(context.TODO(), nsListOptions)
			if err != nil {
				logger.Error("Error getting namespace list", "label", label, "err", err)
				return nil, err
			}
			logger.Debug("Namespaces returned", "count", len(ns.Items))
			for _, namespace := range ns.Items {
				namespaces = append(namespaces, namespace.Name)
			}
		}

	}
	return namespaces, nil
}

func getJobs(clientset kubernetes.Interface, namespaces []string, logger *slog.Logger) ([]podJob, []string, error) {
	labels := strings.Split(*objectLabels, ",")
	jobs := []podJob{}
	jobIDs := []string{}
	toReap := 0
	for _, ns := range namespaces {
		for _, l := range labels {
			listOptions := metav1.ListOptions{
				LabelSelector: l,
			}
			pods, err := clientset.CoreV1().Pods(ns).List(context.TODO(), listOptions)
			if err != nil {
				logger.Error("Error getting pod list", "label", l, "namespace", ns, "err", err)
				metricErrorsTotal.Inc()
				return nil, nil, err
			}
			for _, pod := range pods.Items {
				podLogger := logger.With("pod", pod.Name, "namespace", pod.Namespace)
				var jobID string
				if val, ok := pod.Labels[*jobLabel]; ok {
					podLogger.Debug("Pod has job label", "job", val)
					jobID = val
				} else if *jobLabel == "none" {
					podLogger.Debug("Ignoring absense of job label", "job", "none")
					jobID = "none"
				} else {
					podLogger.Debug("Pod does not have job label, skipping")
					continue
				}
				if !sliceContains(jobIDs, jobID) {
					jobIDs = append(jobIDs, jobID)
				}
				if *reapMax != 0 && toReap >= *reapMax {
					logger.Info("Max reap reached, skipping rest", "max", *reapMax)
					continue
				}
				var lifetime time.Duration
				if val, ok := pod.Annotations[lifetimeAnnotation]; !ok {
					podLogger.Debug("Pod lacks reaper annotation, skipping", "annotation", lifetimeAnnotation)
					continue
				} else {
					podLogger.Debug("Found pod with reaper annotation", "annotation", val)
					lifetime, err = time.ParseDuration(val)
					if err != nil {
						podLogger.Error("Error parsing annotation, SKIPPING", "annotation", val, "err", err)
						metricErrorsTotal.Inc()
						continue
					}
				}
				currentLifetime := timeNow().Sub(pod.CreationTimestamp.Time)
				podLogger.Debug("Pod lifetime", "lifetime", currentLifetime.Seconds())
				if currentLifetime > lifetime {
					podLogger.Debug("Pod is past its lifetime and will be killed.")
					job := podJob{jobID: jobID, podName: pod.Name, namespace: pod.Namespace}
					jobs = append(jobs, job)
				}
			}
		}
	}
	return jobs, jobIDs, nil
}

func getOrphanedJobObjects(clientset kubernetes.Interface, jobs []podJob, jobIDs []string, namespaces []string, logger *slog.Logger) ([]jobObject, error) {
	logger.Debug("JobIDs to evaluate being orphaned", "jobIDs", strings.Join(jobIDs, ","))
	jobObjects := []jobObject{}
	labels := strings.Split(*objectLabels, ",")
	for _, namespace := range namespaces {
		orphanedLogger := logger.With("namespace", namespace)
		for _, l := range labels {
			listOptions := metav1.ListOptions{
				LabelSelector: l,
			}
			services, err := clientset.CoreV1().Services(namespace).List(context.TODO(), listOptions)
			if err != nil {
				orphanedLogger.Error("Error getting services", "err", err)
				metricErrorsTotal.Inc()
				return nil, err
			}
			for _, service := range services.Items {
				if val, ok := service.Labels[*jobLabel]; ok {
					orphanedLogger.Debug("Service has job label", "job", val)
					if !sliceContains(jobIDs, val) {
						orphanedLogger.Debug("Found orphaned Service", "job", val, "name", service.Name, "namespace", service.Namespace)
						jobObject := jobObject{objectType: "service", jobID: val, name: service.Name, namespace: service.Namespace}
						jobObjects = append(jobObjects, jobObject)
					} else {
						orphanedLogger.Debug("Service is not orphaned", "job", val, "name", service.Name, "namespace", service.Namespace)
					}
				} else {
					orphanedLogger.Debug("Service lacks job label", "name", service.Name, "namespace", service.Namespace)
				}
			}
			configmaps, err := clientset.CoreV1().ConfigMaps(namespace).List(context.TODO(), listOptions)
			if err != nil {
				orphanedLogger.Error("Error getting config maps", "err", err)
				metricErrorsTotal.Inc()
				return nil, err
			}
			for _, configmap := range configmaps.Items {
				if val, ok := configmap.Labels[*jobLabel]; ok {
					orphanedLogger.Debug("ConfigMap has job label", "job", val)
					if !sliceContains(jobIDs, val) {
						orphanedLogger.Debug("Found orphaned ConfigMap", "job", val, "name", configmap.Name, "namespace", configmap.Namespace)
						jobObject := jobObject{objectType: "configmap", jobID: val, name: configmap.Name, namespace: configmap.Namespace}
						jobObjects = append(jobObjects, jobObject)
					} else {
						orphanedLogger.Debug("ConfigMap is not orphaned", "job", val, "name", configmap.Name, "namespace", configmap.Namespace)
					}
				} else {
					orphanedLogger.Debug("ConfigMap lacks job label", "name", configmap.Name, "namespace", configmap.Namespace)
				}
			}
			secrets, err := clientset.CoreV1().Secrets(namespace).List(context.TODO(), listOptions)
			if err != nil {
				orphanedLogger.Error("Error getting secrets", "err", err)
				metricErrorsTotal.Inc()
				return nil, err
			}
			for _, secret := range secrets.Items {
				if val, ok := secret.Labels[*jobLabel]; ok {
					orphanedLogger.Debug("Secret has job label", "job", val)
					if !sliceContains(jobIDs, val) {
						orphanedLogger.Debug("Found orphaned Secret", "job", val, "name", secret.Name, "namespace", secret.Namespace)
						jobObject := jobObject{objectType: "secret", jobID: val, name: secret.Name, namespace: secret.Namespace}
						jobObjects = append(jobObjects, jobObject)
					} else {
						orphanedLogger.Debug("Secret is not orphaned", "job", val, "name", secret.Name, "namespace", secret.Namespace)
					}
				} else {
					orphanedLogger.Debug("Secret lacks job label", "name", secret.Name, "namespace", secret.Namespace)
				}
			}
		}
	}
	return jobObjects, nil
}

func getJobObjects(clientset kubernetes.Interface, jobs []podJob, logger *slog.Logger) ([]jobObject, error) {
	jobObjects := []jobObject{}
	for _, job := range jobs {
		jobObjects = append(jobObjects, jobObject{objectType: "pod", jobID: job.jobID, name: job.podName, namespace: job.namespace})
		jobLogger := logger.With("job", job.jobID, "namespace", job.namespace)
		if job.jobID == "none" {
			jobLogger.Debug("Job ID is none, skipping search for additional objects")
			continue
		}
		listOptions := metav1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", *jobLabel, job.jobID),
		}
		services, err := clientset.CoreV1().Services(job.namespace).List(context.TODO(), listOptions)
		if err != nil {
			jobLogger.Error("Error getting services", "err", err)
			metricErrorsTotal.Inc()
			return nil, err
		}
		for _, service := range services.Items {
			jobObject := jobObject{objectType: "service", jobID: job.jobID, name: service.Name, namespace: service.Namespace}
			jobObjects = append(jobObjects, jobObject)
		}
		configmaps, err := clientset.CoreV1().ConfigMaps(job.namespace).List(context.TODO(), listOptions)
		if err != nil {
			jobLogger.Error("Error getting config maps", "err", err)
			metricErrorsTotal.Inc()
			return nil, err
		}
		for _, configmap := range configmaps.Items {
			jobObject := jobObject{objectType: "configmap", jobID: job.jobID, name: configmap.Name, namespace: configmap.Namespace}
			jobObjects = append(jobObjects, jobObject)
		}
		secrets, err := clientset.CoreV1().Secrets(job.namespace).List(context.TODO(), listOptions)
		if err != nil {
			jobLogger.Error("Error getting secrets", "err", err)
			metricErrorsTotal.Inc()
			return nil, err
		}
		for _, secret := range secrets.Items {
			jobObject := jobObject{objectType: "secret", jobID: job.jobID, name: secret.Name, namespace: secret.Namespace}
			jobObjects = append(jobObjects, jobObject)
		}
	}
	return jobObjects, nil
}

func reap(clientset kubernetes.Interface, jobObjects []jobObject, logger *slog.Logger) int {
	deletedPods := 0
	deletedServices := 0
	deletedConfigMaps := 0
	deletedSecrets := 0
	errCount := 0
	for _, job := range jobObjects {
		reapLogger := logger.With("job", job.jobID, "name", job.name, "namespace", job.namespace)
		switch job.objectType {
		case "pod":
			err := clientset.CoreV1().Pods(job.namespace).Delete(context.TODO(), job.name, metav1.DeleteOptions{})
			if err != nil {
				errCount++
				reapLogger.Error("Error deleting pod", "err", err)
				metricErrorsTotal.Inc()
				continue
			}
			reapLogger.Info("Pod deleted")
			metricReapedTotal.With(prometheus.Labels{"type": "pod"}).Inc()
			deletedPods++
		case "service":
			err := clientset.CoreV1().Services(job.namespace).Delete(context.TODO(), job.name, metav1.DeleteOptions{})
			if err != nil {
				errCount++
				reapLogger.Error("Error deleting service", "err", err)
				metricErrorsTotal.Inc()
				continue
			}
			reapLogger.Info("Service deleted")
			metricReapedTotal.With(prometheus.Labels{"type": "service"}).Inc()
			deletedServices++
		case "configmap":
			err := clientset.CoreV1().ConfigMaps(job.namespace).Delete(context.TODO(), job.name, metav1.DeleteOptions{})
			if err != nil {
				errCount++
				reapLogger.Error("Error deleting config map", "err", err)
				metricErrorsTotal.Inc()
				continue
			}
			reapLogger.Info("ConfigMap deleted")
			metricReapedTotal.With(prometheus.Labels{"type": "configmap"}).Inc()
			deletedConfigMaps++
		case "secret":
			err := clientset.CoreV1().Secrets(job.namespace).Delete(context.TODO(), job.name, metav1.DeleteOptions{})
			if err != nil {
				errCount++
				reapLogger.Error("Error deleting secret", "err", err)
				metricErrorsTotal.Inc()
				continue
			}
			reapLogger.Info("Secret deleted")
			metricReapedTotal.With(prometheus.Labels{"type": "secret"}).Inc()
			deletedSecrets++
		}
	}
	logger.Info("Reap summary",
		"pods", deletedPods,
		"services", deletedServices,
		"configmaps", deletedConfigMaps,
		"secrets", deletedSecrets,
	)
	return errCount
}

func metricGathers() prometheus.Gatherers {
	registry := prometheus.NewRegistry()
	registry.MustRegister(metricBuildInfo)
	registry.MustRegister(metricReapedTotal)
	registry.MustRegister(metricError)
	registry.MustRegister(metricErrorsTotal)
	registry.MustRegister(metricDuration)
	gatherers := prometheus.Gatherers{registry}
	if *processMetrics {
		gatherers = append(gatherers, prometheus.DefaultGatherer)
	}
	return gatherers
}

func sliceContains(slice []string, str string) bool {
	for _, s := range slice {
		if str == s {
			return true
		}
	}
	return false
}
