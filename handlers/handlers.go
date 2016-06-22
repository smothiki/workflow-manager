package handlers

// handler echoes the HTTP request.
import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/arschles/kubeapp/api/rc"
	"github.com/deis/workflow-manager/config"
	"github.com/deis/workflow-manager/data"
	apiclient "github.com/deis/workflow-manager/pkg/swagger/client"
	"github.com/deis/workflow-manager/pkg/swagger/client/operations"
	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
)

const (
	componentsRoute = "/components" // resource value for components route
	idRoute         = "/id"         // resource value for ID route
	doctorRoute     = "/doctor"
)

func createHTTPClient(sslVerify bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: !sslVerify},
		DisableKeepAlives: true,
		Proxy:             http.ProxyFromEnvironment,
	}
	return &http.Client{Transport: tr}
}

func checkAdminAuth(r *http.Request) ([]string, error) {
	sslVerify, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return []string{}, errors.New("cannot read the request body")
	}
	if string(sslVerify) == "skip" {
		return []string{}, nil
	}
	urlc := strings.SplitAfterN(r.Host, ".", 2)[1]
	controllerHost := "deis." + urlc
	r.Host = controllerHost
	req, err := http.NewRequest("GET", "http://"+controllerHost+"/v2/users?limit=1", nil)
	req.Header.Add("Content-Type", "application/json")
	req.Header["Authorization"] = r.Header["Authorization"]
	req.Header["User-Agent"] = r.Header["User-Agent"]
	c := createHTTPClient(string(sslVerify) == "true")
	res, err := c.Do(req)
	return res.Header["DEIS_API_VERSION"], err
}

// RegisterRoutes attaches handler functions to routes
func RegisterRoutes(
	r *mux.Router,
	secretGetterCreator data.KubeSecretGetterCreator,
	rcLister rc.Lister,
	availableVersions data.AvailableVersions,
) *mux.Router {

	clusterID := data.NewClusterIDFromPersistentStorage(secretGetterCreator)
	r.Handle(componentsRoute, ComponentsHandler(
		data.NewInstalledDeisData(rcLister),
		clusterID,
		data.NewLatestReleasedComponent(secretGetterCreator, rcLister, availableVersions),
		secretGetterCreator,
	))
	r.Handle(idRoute, IDHandler(clusterID))
	doctorAPIClient, _ := config.GetSwaggerClient(config.Spec.DoctorAPIURL)
	r.Handle(doctorRoute, DoctorHandler(
		data.NewInstalledDeisData(rcLister),
		clusterID,
		data.NewLatestReleasedComponent(secretGetterCreator, rcLister, availableVersions),
		secretGetterCreator,
		doctorAPIClient,
	)).Methods("POST")
	return r
}

// ComponentsHandler route handler
func ComponentsHandler(
	c data.InstalledData,
	i data.ClusterID,
	v data.AvailableComponentVersion,
	secretGetterCreator data.KubeSecretGetterCreator,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cluster, err := data.GetCluster(c, i, v, secretGetterCreator)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(w).Encode(cluster); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

// DoctorHandler route handler
func DoctorHandler(
	c data.InstalledData,
	i data.ClusterID,
	v data.AvailableComponentVersion,
	secretGetterCreator data.KubeSecretGetterCreator,
	apiClient *apiclient.WorkflowManager,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controllerVersion, err := checkAdminAuth(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		doctor, err := data.GetDoctorInfo(c, i, v, secretGetterCreator)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		uid := uuid.NewV4().String()
		_, err = apiClient.Operations.PublishDoctorInfo(&operations.PublishDoctorInfoParams{Body: &doctor, UUID: uid})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(controllerVersion) > 0 {
			w.Header().Set("DEIS_API_VERSION", controllerVersion[0])
		}
		writePlainText(uid, w)
	})
}

// IDHandler route handler
func IDHandler(getter data.ClusterID) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := data.GetID(getter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writePlainText(id, w)
	})
}

// writePlainText is a helper function for writing HTTP text data
func writePlainText(text string, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(text))
}
