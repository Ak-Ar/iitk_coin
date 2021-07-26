package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
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
	http.HandleFunc("/awarding", awarding)
	http.HandleFunc("/transfer", transferCoins)
	http.HandleFunc("/checkbalance", checkBal)
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

type Awarding struct {
	Rollno string  `json:"rollno"`
	Coin   float32 `json:"awardingcoins"`
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

func database(rollno int, name string, password string, emailid string, coins float32) {
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("opening database")
	createtable(db)
	fmt.Println("forming table if not exists")
	insertingdata := `INSERT INTO student(rollno,name,password,emailid,coins) VALUES (?,?,?,?,?)`
	statement, err := db.Prepare(insertingdata)
	statement.Exec(rollno, name, password, emailid, coins)
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
		"coins" REAL,
		"admin" TEXT,
		
		unique(rollno));` //sql statement for creating table
	statement, err := db.Prepare(creatingtable)
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec() //executing sql statements
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////                      IMPORTANT FUNCTIONS                       /////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
func authentication(w http.ResponseWriter, r *http.Request) int {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return -1

		}
		w.WriteHeader(http.StatusBadRequest)
		return -1

	}

	tknStr := c.Value
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil

	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return -1
		}
		w.WriteHeader(http.StatusBadRequest)
		return -1
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return -1
	}
	roll, _ := strconv.Atoi(claims.Username)
	return roll
}

func signedUp(rollno string) int {
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("opening database")
	rows, _ := db.Query("SELECT rollno FROM student")
	var savedRollno string
	for rows.Next() {
		rows.Scan(&savedRollno)
		if savedRollno == rollno {
			defer db.Close()
			return 1
		}
	}
	return 0
}

func fetchCoins(rollno string) float32 {
	fmt.Printf("user %s whose balance is to be found \n", rollno)
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("opening database")
	rows, _ := db.Query("SELECT rollno ,coins FROM student")
	var savedRollno string
	var availCoins float32
	for rows.Next() {
		rows.Scan(&savedRollno, &availCoins)
		if savedRollno == rollno {
			fmt.Printf("user balance found \n")
			return availCoins
		}
	}
	return -1
}

func batch(rollno string) int {
	en, _ := strconv.Atoi(rollno)
	for en > 100 {
		en = en / 10
	}
	return en
}

func importantMembers(rollno string) bool {
	file1, err := os.Open("coreteam.txt")
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	file2, err := os.Open("AH.txt")
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	file3, err := os.Open("gensec.txt")
	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}
	scanner1 := bufio.NewScanner(file1)
	scanner1.Split(bufio.ScanLines)
	for scanner1.Scan() {
		if rollno == scanner1.Text() {
			return true
		}
	}
	file1.Close()
	scanner2 := bufio.NewScanner(file2)
	scanner2.Split(bufio.ScanLines)
	for scanner2.Scan() {
		if rollno == scanner2.Text() {
			return true
		}
	}
	file2.Close()
	scanner3 := bufio.NewScanner(file3)
	scanner3.Split(bufio.ScanLines)
	for scanner3.Scan() {
		if rollno == scanner3.Text() {
			return true
		}
	}
	file3.Close()
	fmt.Printf("admin access denied \n")
	return false
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
		database(en, n, hashedPassword, e, 0.0)
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
			expirationTime := time.Now().Add(5 * time.Minute)
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
	defer db.Close()
}
func welcome(w http.ResponseWriter, r *http.Request) {
	rollno := authentication(w, r)
	if rollno != -1 {
		w.Write([]byte(fmt.Sprintf("Welcome %d!", rollno)))
	} else {
		fmt.Fprintf(w, "user not logged in")
	}
}

func awarding(w http.ResponseWriter, r *http.Request) {
	adminRoll := strconv.Itoa(authentication(w, r))
	if importantMembers(adminRoll) {
		fmt.Printf("admin %s is logged in \n", adminRoll)

		var coins Awarding
		err := json.NewDecoder(r.Body).Decode(&coins)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		db, err := sql.Open("sqlite3", "./data.db")
		if err != nil {
			log.Fatal(err.Error())
		}
		fmt.Println("database accessed")
		db.Exec("PRAGMA journal_mode=WAL;")
		tx, err := db.Begin()
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("ok1")
		rows, _ := db.Query("SELECT rollno, coins FROM student")
		var savedrollno string
		var coin float32
		defer rows.Close()
		fmt.Println("user to be find", coins.Rollno)
		for rows.Next() {
			rows.Scan(&savedrollno, &coin)
			fmt.Println("current username ", savedrollno)
			if savedrollno == coins.Rollno {
				fmt.Println("found user")
				_, err := db.Exec("UPDATE student SET coins = coins + ? WHERE rollno = ?", coins.Coin, coins.Rollno)
				if err != nil {
					tx.Rollback()
					log.Fatalln(err.Error())
				}
				fmt.Println("awarded ", coins.Coin, "to the user specified")

			}
		}
		tx.Commit()
		defer db.Close()
		fmt.Println("adding coins successful")
	}
}

func transferCoins(w http.ResponseWriter, r *http.Request) {
	Roll := authentication(w, r)
	userRoll := strconv.Itoa(Roll)
	var transferData Awarding
	err := json.NewDecoder(r.Body).Decode(&transferData)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	fmt.Printf("logged in user roll: %s \n", userRoll)
	fmt.Printf("recepient data roll no : %s coins to be transferred : %g \n", transferData.Rollno, transferData.Coin)
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Printf("database accessed")
	db.Exec("PRAGMA journal_mode=WAL;")
	if signedUp(transferData.Rollno) == 0 {
		fmt.Printf("User has not signed up")
		return
	}
	fmt.Printf("user %s is signed up \n", transferData.Rollno)
	batch1 := batch(userRoll)
	batch2 := batch(transferData.Rollno)
	fmt.Printf("batch of sender: %d and reciepient: %d \n", batch1, batch2)
	var actual float32
	var tax float32
	balance := fetchCoins(transferData.Rollno)
	fmt.Printf("balance of sender is %g \n", balance)
	if batch1 == batch2 {
		tax = 0.02 * transferData.Coin
		actual = transferData.Coin + tax
	} else {
		tax = 0.33 * transferData.Coin
		actual = transferData.Coin + tax
	}
	fmt.Printf("tax : %g total amount: %g \n", tax, actual)
	if balance < actual {
		fmt.Printf("insuffecient balance\n")
		return
	} else {
		fmt.Printf("transaction started \n")
		tx, err := db.Begin()
		if err != nil {
			fmt.Println(err)
		}
		_, err = db.Exec("UPDATE student SET coins = coins - ?  WHERE rollno = ? ", actual, userRoll)
		if err != nil {
			fmt.Println("Error1")
			tx.Rollback()
			return
		}
		fmt.Printf("amount deducted \n")
		_, err = db.Exec("UPDATE student SET coins = coins + ? WHERE rollno = ?", transferData.Coin, transferData.Rollno)
		if err != nil {
			fmt.Println("Error2")
			tx.Rollback()
			return
		}
		fmt.Printf("amount added")
		err = tx.Commit()
		if err != nil {
			fmt.Println(err)
			tx.Rollback()
			return
		}
		fmt.Printf("changes commited \n")
	}

	fmt.Fprintf(w, "Coin Transfer successful\n")
}

func checkBal(w http.ResponseWriter, r *http.Request) {
	rollno := strconv.Itoa(authentication(w, r))
	coins := fetchCoins(rollno)
	fmt.Fprintf(w, "HI %s you have %g coins", rollno, coins)
}
