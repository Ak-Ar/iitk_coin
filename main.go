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
	http.HandleFunc("/redeem", redeemhandler)
	http.HandleFunc("/additems", additemhandler)
	http.HandleFunc("/status", statushandler)
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

type Item struct {
	Product   string  `json:"product"`
	Coin      float32 `json:"cost"`
	Available string  `json:"status"`
	Quantity  int     `json:"quantity"`
	Option    int     `json:"option"`
}

type stat struct {
	Status string `json:"status"`
	rollno string `josn:"rollno"`
}
type Request struct {
	item string `json:"item"`
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////                        ERROR HANDLERS                          /////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////                        DATABASE FUNCTIONS AND DECLARATION                ///////////////////////////////////////
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
	insertingdata := `INSERT INTO student(rollno,name,password,emailid,coins,tax, time) VALUES (?,?,?,?,?)`
	statement, err := db.Prepare(insertingdata)
	statement.Exec(rollno, name, password, emailid, coins)
	if err != nil {
		log.Fatalln(err.Error())
	}
	fmt.Println("inserted user information in database")
	defer db.Close()
}

func redeem() {
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("creating table redeem if not exists")
	creatingtable := `CREATE TABLE IF NOT EXISTS redeem(
		"ID" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"HOST" TEXT ,
		"AWARDEE" TEXT NOT NULL,
		"ITEM" TEXT NOT NULL ,
		"COST" REAL NOT NULL,
		"STATUS" TEXT NOT NULL);`
	statement, err := db.Prepare(creatingtable)
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec()
	defer db.Close()
}

func additemstable() {
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("creating table products if not exists")
	creatingtable := `CREATE TABLE IF NOT EXISTS products(
		"ID" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"PRODUCT" TEXT NOT NULL,
		"COINS" TEXT NOT NULL,
		"AVAILABLE_STATUS" TEXT NOT NULL, 
		"QUANTITY" INTEGER );`
	statement, err := db.Prepare(creatingtable)
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec()
	defer db.Close()
}

func transactiontable() {
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("forming table if not exists")
	creatingtable := `CREATE TABLE IF NOT EXISTS history(
		"ID" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"SENDER" TEXT NOT NULL,
		"RECEPIENT" TEXT NOT NULL,
		"AMOUNT" REAL NOT NULL,
		"TAX" REAL,
		"REASON" TEXT,
		"TIME" TEXT);`
	statement, err := db.Prepare(creatingtable)
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec()
	defer db.Close()
}

func createtable(db *sql.DB) {
	creatingtable := `CREATE TABLE IF NOT EXISTS student(
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"rollno" TEXT NOT NULL,
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

func importantMembers(rollno string, check int8) bool {
	switch check {
	case 1:
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

	case 2:
		file2, err := os.Open("AH.txt")
		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}
		file3, err := os.Open("gensec.txt")
		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}
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

	case 3:
		file1, err := os.Open("coreteam.txt")
		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}
		scanner1 := bufio.NewScanner(file1)
		scanner1.Split(bufio.ScanLines)
		for scanner1.Scan() {
			if rollno == scanner1.Text() {
				file1.Close()
				return true
			}
		}
		file1.Close()

	}
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
		transactiontable() //creating transaaction table to keep a record about the transactions
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
	transactiontable()
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
	if importantMembers(adminRoll, 1) {
		fmt.Printf("admin %s is logged in \n", adminRoll)

		var coins Awarding
		err := json.NewDecoder(r.Body).Decode(&coins)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if coins.Rollno == adminRoll {
			fmt.Printf("Failure!awarding coin to own account\n")
			fmt.Fprintf(w, "u cannot award coins to yourself\n")
			return
		}
		if importantMembers(coins.Rollno, 2) {
			fmt.Printf("accounts of gensec and ah members are freezed in the their tenure \n")
			fmt.Fprintf(w, "accounts of gensec and ah members are freezed in the their tenure \n")
			return
		}
		if importantMembers(coins.Rollno, 3) {
			if !(importantMembers(adminRoll, 2)) {
				fmt.Printf("coins can be awarded to a core team member is possible only by gensec or AH\n")
				fmt.Fprintf(w, "coins can be awarded to a core team member is possible only by gensec or AH\n")
				return
			}
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
		if signedUp(coins.Rollno) == 0 {
			fmt.Printf("User has not signed up\n")
			return
		}
		fmt.Printf("user %s is signed up \n", coins.Rollno)
		fmt.Println("user to be find", coins.Rollno)
		_, err = db.Exec("UPDATE student SET coins = coins + ? WHERE rollno = ?", coins.Coin, coins.Rollno)
		if err != nil {
			tx.Rollback()
			log.Fatalln(err.Error())
		}
		fmt.Println("awarded ", coins.Coin, "to the user specified")
		_, err = db.Exec("INSERT INTO history(SENDER, RECEPIENT, AMOUNT,TAX, REASON,TIME) VALUES (?,?,?,?,?,?)", adminRoll, coins.Rollno, coins.Coin, 0.0, "award", time.Now().String())
		if err != nil {
			fmt.Println("Error3")
			tx.Rollback()
		}
		fmt.Printf("transaction history recorded\n")
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
	if userRoll == transferData.Rollno {
		fmt.Printf("FAILURE!! transferring to own account\n")
		fmt.Fprintf(w, "You cannot transfer coins to your own account\n")
		return
	}
	if importantMembers(transferData.Rollno, 1) {
		fmt.Printf("transfer coins to gensec , AH or core team members are not possible\n")
		fmt.Fprintf(w, "transfer coins  to gensec , AH or core team members are not possible\n ")
		return
	}

	fmt.Printf("recepient data roll no : %s coins to be transferred : %g \n", transferData.Rollno, transferData.Coin)
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Printf("database accessed\n")
	db.Exec("PRAGMA journal_mode=WAL;")
	if signedUp(transferData.Rollno) == 0 {
		fmt.Printf("User has not signed up\n")
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
		}
		fmt.Printf("amount deducted \n")
		_, err = db.Exec("UPDATE student SET coins = coins + ? WHERE rollno = ?", transferData.Coin, transferData.Rollno)
		if err != nil {
			fmt.Println("Error2")
			tx.Rollback()
		}
		fmt.Printf("amount added")
		_, err = db.Exec("INSERT INTO history(SENDER, RECEPIENT, AMOUNT,TAX, REASON,TIME) VALUES (?,?,?,?,?,?)", userRoll, transferData.Rollno, transferData.Coin, tax, "transfer", time.Now().String())
		if err != nil {
			fmt.Println("Error3")
			tx.Rollback()
		}
		fmt.Printf("transaction history recorded\n")
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

func redeemhandler(w http.ResponseWriter, r *http.Request) {
	rollno := strconv.Itoa(authentication(w, r))
	var item Request
	err := json.NewDecoder(r.Body).Decode(&item)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	redeem()
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}

	rows, _ := db.Query("SELECT PRODUCT ,COINS,QUNATITY FROM products")
	var product string
	var coins float32
	for rows.Next() {
		rows.Scan(&savedRollno, &availCoins)
		if savedRollno == rollno {
			fmt.Printf("user balance found \n")
			return availCoins
		}
	}

	_, err = db.Exec("INSERT INTO redeem(AWARDEE,ITEM,COST,STATUS) VALUES(?,?,?,?)", rollno, item.item, cost, "pending")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Printf("Added your request :)\n")

}

func additemhandler(w http.ResponseWriter, r *http.Request) {
	rollno := strconv.Itoa(authentication(w, r))
	if !(importantMembers(rollno, 1)) {
		fmt.Fprintf(w, "You are unauthorized to access this page")
		fmt.Printf("unauthorized access to this page")
		return
	}
	fmt.Printf("%s has logged in with admin tag\n", rollno)
	var product Item
	err := json.NewDecoder(r.Body).Decode(&product)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	additemstable()
	if product.Option == 1 {
		_, err = db.Exec("INSERT INTO products(PRODUCT,COINS,AVAILABLE_STATUS,QUANTITY) VALUES(?,?,?,?)", product.Product, product.Coin, product.Available, product.Quantity)
		if err != nil {
			log.Fatal(err.Error())
		}
		fmt.Printf("Added items to database :)\n")
	}
	if product.Option == 2 {
		_, err = db.Exec("UPDATE products set AVAILABLE_STATUS = ? , QUANTITY =? WHERE PRODUCT =?", product.Available, product.Quantity, product.Product)
		if err != nil {
			log.Fatal(err.Error())
		}
		fmt.Printf("Updated items in database :)\n")
	}
	defer db.Close()
}

func statushandler(w http.ResponseWriter, r *http.Request) {
	rollno := strconv.Itoa(authentication(w, r))
	if !(importantMembers(rollno, 1)) {
		fmt.Fprintf(w, "You are unauthorized to access this page")
		fmt.Printf("unauthorized access to this page")
		return
	}
	fmt.Printf("%s has logged in with admin tag\n", rollno)
	redeem()
	db, err := sql.Open("sqlite3", "./data.db")
	if err != nil {
		log.Fatal(err.Error())
	}
	var sta stat
	err = json.NewDecoder(r.Body).Decode(&sta)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, err = db.Exec("UPDATE redeem SET STATUS status = ?, HOST =? WHERE AWARDEE = ?", sta.Status, rollno, sta.rollno)
	defer db.Close()
}
