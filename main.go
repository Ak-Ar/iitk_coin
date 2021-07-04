package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("itissimple")

func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signuphandler)
	http.HandleFunc("/welcome", welcome)
	log.Fatal(http.ListenAndServe(":8080", nil))
	fmt.Printf("Starting the server")
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////                        VARIABLE STRUCTS                        /////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////                        ERROR HANDLERS                          /////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////                        DATABASE STRUCTURES                     /////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func hashPassword(password string) (string, error) {
	var passwordBytes = []byte(password)
	hashedPasswordBytes, err := bcrypt.
		GenerateFromPassword(passwordBytes, bcrypt.MinCost)

	return string(hashedPasswordBytes), err
}

func doPasswordsMatch(hashedPassword, currPassword string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword), []byte(currPassword))
	return err == nil
}

func database(rollno int, name string, password string, emailid string) {
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("opening database")
	createtable(db)
	fmt.Println("forming table if not exists")
	insertingdata := `INSERT INTO student(rollno,name,password,emailid) VALUES (?,?,?,?)`
	statement, err := db.Prepare(insertingdata)
	statement.Exec(rollno, name, password, emailid)
	if err != nil {
		log.Fatalln(err.Error())
	}
	fmt.Println("inserted user information in database")
	defer db.Close()
}

func createtable(db *sql.DB) {
	creatingtable := `CREATE TABLE IF NOT EXISTS student(
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"rollno" TEXT NOT NULL ,
		"name" TEXT NOT NULL,
		"password" TEXT NULL,
		"emailid" TEXT NULL,
		unique(rollno));` //sql statement for creating table
	statement, err := db.Prepare(creatingtable)
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec() //executing sql statements
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////                       ENDPOINT HANDLERS                        /////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func signuphandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("method:", r.Method) //get request method
	if r.Method == "GET" {
		t, _ := template.ParseFiles("signup.gtpl")
		t.Execute(w, nil)
	} else {
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}

		rn := r.FormValue("rollno")
		en, _ := strconv.Atoi(rn)
		n := r.FormValue("username")
		e := r.FormValue("emailid")
		var hashedPassword, err = hashPassword(r.FormValue("password"))
		if err != nil {
			println(fmt.Println("Error hashing password: ", err))
			return
		}
		database(en, n, hashedPassword, e)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	fmt.Println("opening data base")
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	rows, _ := db.Query("SELECT rollno, password FROM student")
	var savedRollno string
	var savedPassword string
	for rows.Next() {
		rows.Scan(&savedRollno, &savedPassword)
		if savedRollno == creds.Username {
			if !(doPasswordsMatch(savedPassword, creds.Password)) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			expirationTime := time.Now().Add(2 * time.Minute)
			claims := &Claims{
				Username: creds.Username,
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: expirationTime.Unix(),
				},
			}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(jwtKey)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:    "token",
				Value:   tokenString,
				Expires: expirationTime,
			})
		}

	}

}
func welcome(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tknStr := c.Value
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Welcome %s!", claims.Username)))
}
