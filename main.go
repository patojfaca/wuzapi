package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/patrickmn/go-cache"
	"go.mau.fi/whatsmeow/store/sqlstore"
	waLog "go.mau.fi/whatsmeow/util/log"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	_ "modernc.org/sqlite"
)

type server struct {
	db     *sql.DB
	router *mux.Router
	exPath string
}

var (
	address     = flag.String("address", "0.0.0.0", "Bind IP Address")
	port        = flag.String("port", "9000", "Listen Port")
	waDebug     = flag.String("wadebug", "", "Enable whatsmeow debug (INFO or DEBUG)")
	logType     = flag.String("logtype", "console", "Type of log output (console or json)")
	colorOutput = flag.Bool("color", false, "Enable colored output for console logs")
	//sslcert     = flag.String("sslcertificate", "", "SSL Certificate File")
	//sslprivkey  = flag.String("sslprivatekey", "", "SSL Certificate Private Key File")
	adminToken = flag.String("admintoken", "", "Security Token to authorize admin actions (list/create/remove users)")
	container  *sqlstore.Container

	killchannel   = make(map[int](chan bool))
	userinfocache = cache.New(5*time.Minute, 10*time.Minute)
	log           zerolog.Logger
)

func init() {
	flag.Parse()

	err := godotenv.Load()
	if err != nil {
		fmt.Println("Erro ao carregar o arquivo .env:", err)
	}

	if *logType == "json" {
		log = zerolog.New(os.Stdout).With().Timestamp().Str("role", filepath.Base(os.Args[0])).Logger()
	} else {
		output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339, NoColor: !*colorOutput}
		log = zerolog.New(output).With().Timestamp().Logger()
		//log = zerolog.New(output).With().Timestamp().Str("role", filepath.Base(os.Args[0])).Logger()
	}

	if *adminToken == "" {
		if v := os.Getenv("WUZAPI_ADMIN_TOKEN"); v != "" {
			*adminToken = v
		}
	}

}

func decodeBase64ToFile(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	tmpFile, err := ioutil.TempFile("", "cert-*.pem")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(data); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

func main() {

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	dbDirectory := exPath + "/dbdata"
	_, err = os.Stat(dbDirectory)
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(dbDirectory, 0751)
		if errDir != nil {
			panic("Could not create dbdata directory")
		}
	}

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	certificateBase64 := os.Getenv("CERTIFICATE")
	sslkeyBase64 := os.Getenv("SSLKEY")
	//log.Info().Str("certificate", certificate).Str("sslkey", sslkey).Msg("certificate")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", dbUser, dbPassword, dbHost, dbPort, dbName)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal().Err(err).Msg("Could not open MySQL connection")
		os.Exit(1)
	}

	sqlStmt := `
		CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			token VARCHAR(255) NOT NULL,
			webhook VARCHAR(255) NOT NULL DEFAULT '',
			jid VARCHAR(255) NOT NULL DEFAULT '',
			qrcode VARCHAR(255) NOT NULL DEFAULT '',
			connected TINYINT DEFAULT 0,
			expiration BIGINT,
			events TEXT NOT NULL
		);`
	_, err = db.Exec(sqlStmt)
	if err != nil {
		panic(fmt.Sprintf("%q: %s\n", err, sqlStmt))
	}

	if *waDebug != "" {
		dbLog := waLog.Stdout("Database", *waDebug, *colorOutput)
		dsn := "user:password@tcp(127.0.0.1:3306)/dbname?parseTime=true"
		container, err = sqlstore.New("mysql", dsn, dbLog)
	} else {
		container, err = sqlstore.New("sqlite", "file:"+exPath+"/dbdata/main.db?_pragma=foreign_keys(1)&_busy_timeout=3000", nil)
	}
	if err != nil {
		panic(err)
	}

	s := &server{
		router: mux.NewRouter(),
		db:     db,
		exPath: exPath,
	}
	s.routes()

	s.connectOnStartup()

	srv := &http.Server{
		Addr:              *address + ":" + *port,
		Handler:           s.router,
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       180 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		var certPath, keyPath string
		var err error

		if certificateBase64 != "" && sslkeyBase64 != "" {
			certPath, err = decodeBase64ToFile(certificateBase64)
			if err != nil {
				log.Error().Msg("Erro ao decodificar certificado:")
			}

			keyPath, err = decodeBase64ToFile(sslkeyBase64)
			if err != nil {
				log.Error().Msg("Erro ao decodificar chave SSL:")
			}
		}

		if certPath != "" && keyPath != "" {
			srv := &http.Server{
				Addr:              *address + ":443",
				Handler:           s.router,
				ReadHeaderTimeout: 20 * time.Second,
				ReadTimeout:       60 * time.Second,
				WriteTimeout:      120 * time.Second,
				IdleTimeout:       180 * time.Second,
			}

			// Verifica se os arquivos são válidos
			_, errCert := tls.LoadX509KeyPair(certPath, keyPath)
			if errCert != nil {
				log.Error().Msg("Erro ao carregar certificado SSL:")
			}

			// Inicia o servidor HTTPS
			log.Info().Msg("Starting HTTPS server...")
			if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
				log.Error().Msg("Startup failed:")
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				//log.Fatalf("listen: %s\n", err)
				log.Fatal().Err(err).Msg("Startup failed")
			}
		}

		/*if *sslcert != "" {
			if err := srv.ListenAndServeTLS(*sslcert, *sslprivkey); err != nil && err != http.ErrServerClosed {
				//log.Fatalf("listen: %s\n", err)
				log.Fatal().Err(err).Msg("Startup failed")
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				//log.Fatalf("listen: %s\n", err)
				log.Fatal().Err(err).Msg("Startup failed")
			}
		}*/
	}()
	//wlog.Infof("Server Started. Listening on %s:%s", *address, *port)
	log.Info().Str("address", *address).Str("port", *port).Msg("Server Started")

	<-done
	log.Info().Msg("Server Stoped")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		// extra handling here
		cancel()
	}()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Str("error", fmt.Sprintf("%+v", err)).Msg("Server Shutdown Failed")
		os.Exit(1)
	}
	log.Info().Msg("Server Exited Properly")
}
