package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"authguard/adapters/golang/access"
	authfilter "authguard/adapters/golang/filter"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/controller"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/dto"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/repository"
	"authguard/use-cases/customer-growth-job-service/e2e/deploy/golang-sqlx-service/pkg/service"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

func main() {
	database := openDatabase()
	defer database.Close()

	jobRepository := repository.NewCustomerGrowthJobRepository(database)
	jobService := service.NewCustomerGrowthJobService(jobRepository)
	jobController := controller.NewCustomerGrowthJobController(jobService)
	headerResolver, err := access.NewHeaderAccessContextResolverFromEnv()
	if err != nil {
		log.Fatalf("initialize Authguard direct-context resolver: %v", err)
	}
	resolvers := []access.IAccessContextResolver{headerResolver}
	var tokenResolver *access.GRPCAccessContextResolver
	if strings.TrimSpace(os.Getenv(access.GRPCTargetEnv)) != "" {
		resolver, err := access.NewGRPCAccessContextResolverFromEnv()
		if err != nil {
			log.Fatalf("initialize Authguard scope resolver: %v", err)
		}
		tokenResolver = &resolver
		resolvers = append(resolvers, resolver)
	}
	if tokenResolver != nil {
		defer tokenResolver.Close()
	}

	authorized := authfilter.NewAccessMiddleware(resolvers...).Wrap(newJobHandler(jobController))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("ok"))
	})
	mux.Handle("/customer-growth/jobs", authorized)
	mux.Handle("/customer-growth/jobs/", authorized)

	server := &http.Server{
		Addr:              ":" + environmentOrDefault("PORT", "8080"),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("customer-growth-job service listening on %s", server.Addr)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func openDatabase() *sqlx.DB {
	driver := environmentOrDefault("DATABASE_DRIVER", "pgx")
	database, err := sqlx.Open(driver, requiredEnvironment("DATABASE_URL"))
	if err != nil {
		log.Fatalf("open customer growth database: %v", err)
	}
	database.SetMaxOpenConns(16)
	database.SetMaxIdleConns(4)
	database.SetConnMaxLifetime(30 * time.Minute)
	if err := database.Ping(); err != nil {
		log.Fatalf("ping customer growth database: %v", err)
	}
	return database
}

func newJobHandler(controller *controller.CustomerGrowthJobController) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		id, hasID, err := pathID(request.URL.Path)
		if err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		switch {
		case request.Method == http.MethodGet && !hasID:
			jobs, err := controller.ListVisibleJobs(request.Context(), dto.CustomerGrowthJobSearchRequest{
				WorkspaceID: request.URL.Query().Get("workspace_id"),
				ProjectID:   request.URL.Query().Get("project_id"),
				Status:      request.URL.Query().Get("status"),
				OwnerUserID: request.URL.Query().Get("owner_user_id"),
			})
			writeJSONResult(response, jobs, err)
		case request.Method == http.MethodGet && hasID:
			job, found, err := controller.GetJob(request.Context(), id)
			if err == nil && !found {
				err = repository.ErrCustomerGrowthJobNotFound
			}
			writeJSONResult(response, job, err)
		case request.Method == http.MethodPost && !hasID:
			var input dto.CreateCustomerGrowthJobRequest
			if !decodeJSON(response, request, &input) {
				return
			}
			job, err := controller.CreateJob(request.Context(), input)
			writeJSONResult(response, job, err)
		case request.Method == http.MethodPut && hasID:
			var input dto.UpdateCustomerGrowthJobRequest
			if !decodeJSON(response, request, &input) {
				return
			}
			job, err := controller.UpdateJob(request.Context(), id, input)
			writeJSONResult(response, job, err)
		case request.Method == http.MethodDelete && hasID:
			err := controller.DeleteJob(request.Context(), id)
			if err != nil {
				writeServiceError(response, err)
				return
			}
			response.WriteHeader(http.StatusNoContent)
		default:
			writeError(response, http.StatusMethodNotAllowed, errors.New("unsupported operation"))
		}
	})
}

func pathID(path string) (int64, bool, error) {
	value := strings.TrimPrefix(path, "/customer-growth/jobs")
	if value == "" || value == "/" {
		return 0, false, nil
	}
	value = strings.TrimPrefix(value, "/")
	if strings.Contains(value, "/") {
		return 0, false, errors.New("invalid customer growth job path")
	}
	id, err := strconv.ParseInt(value, 10, 64)
	return id, true, err
}

func decodeJSON(response http.ResponseWriter, request *http.Request, output any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeJSONResult(response http.ResponseWriter, value any, err error) {
	if err != nil {
		writeServiceError(response, err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func writeServiceError(response http.ResponseWriter, err error) {
	if errors.Is(err, repository.ErrCustomerGrowthJobNotFound) {
		writeError(response, http.StatusNotFound, err)
		return
	}
	if errors.Is(err, access.ErrAccessContextUnavailable) {
		writeError(response, http.StatusUnauthorized, err)
		return
	}
	writeError(response, http.StatusForbidden, err)
}

func writeError(response http.ResponseWriter, status int, err error) {
	http.Error(response, fmt.Sprintf("%d: %s", status, err), status)
}

func requiredEnvironment(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("%s is required", name)
	}
	return value
}

func environmentOrDefault(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}
