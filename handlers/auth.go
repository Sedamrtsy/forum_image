package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"

	"forum/utils"
)

var config Config

type Config struct {
	GoogleClientID       string `json:"google_client_id"`
	GoogleClientSecret   string `json:"google_client_secret"`
	GitHubClientID       string `json:"github_client_id"`
	GitHubClientSecret   string `json:"github_client_secret"`
	FacebookClientID     string `json:"facebook_client_id"`
	FacebookClientSecret string `json:"facebook_client_secret"`
}

func loadConfig() {
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Failed to open config file: %s", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file) // JSON verisini okuyup anlamaya çalışır.
	err = decoder.Decode(&config)    //JSON verisini okur ve Go yapısına dönüştürür.
	if err != nil {
		log.Fatalf("Failed to decode config file: %s", err)
	}
}

// oauth2.Config tipinde, OAuth2 yapılandırma ayarlarını tutmak için kullanılıyor.
var (
	googleOauthConfig   *oauth2.Config
	githubOauthConfig   *oauth2.Config
	facebookOauthConfig *oauth2.Config
)

var (
	oauthStateString         = "random"
	oauthStateStringGitHub   = "random"
	facebookOauthStateString = "random"
)

// init fonksiyonu, uygulama başlatıldığında çalışır ve googleOauthConfig yapılandırma değişkenini ayarlar.
//Bu değişken OAuth2 kimlik doğrulaması için gerekli tüm bilgileri içerir.
func init() {
	loadConfig()
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8040/auth/google/callback", // Google OAuth2 işlemi tamamlandıktan sonra yönlendirilecek URL.
		ClientID:     config.GoogleClientID,
		ClientSecret: config.GoogleClientSecret,
		Scopes: []string{ //Kullanıcının izni ile erişilecek veriler.
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	githubOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8040/auth/github/callback",
		ClientID:     config.GitHubClientID,
		ClientSecret: config.GitHubClientSecret,
		Scopes:       []string{"read:user", "user:email"},
		Endpoint: oauth2.Endpoint{ //bir kullanıcının uygulamanıza erişim izni vermesi
			AuthURL:  "https://github.com/login/oauth/authorize",    //Kullanıcı, uygulamanıza izin verir ve bir yetkilendirme kodu döndürülür.
			TokenURL: "https://github.com/login/oauth/access_token", //Yetkilendirme kodunu erişim tokenına dönüştüren URL.
		},
	}
	facebookOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8040/auth/facebook/callback",
		ClientID:     config.FacebookClientID,
		ClientSecret: config.FacebookClientSecret,
		Scopes: []string{
			"email",
		},
		Endpoint: facebook.Endpoint,
	}
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	oauthStateString = generateNonce() + ":GoogleLogin" //kimlik doğrulama işlemi ,state
	url := googleOauthConfig.AuthCodeURL(oauthStateString, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect) //yetkilendirme URL'sine yönlendir
}

func handleGoogleRegister(w http.ResponseWriter, r *http.Request) {
	oauthStateString = generateNonce() + ":GoogleRegister"
	url := googleOauthConfig.AuthCodeURL(oauthStateString, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state") //güvenliği artırmak
	stateParts := strings.Split(state, ":")
	if len(stateParts) != 2 || stateParts[0] != strings.Split(oauthStateString, ":")[0] {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	value := stateParts[1]
	//Google tarafından geri yönlendirilen URL'den code parametresini alır.
	code := r.FormValue("code")
	token, err := googleOauthConfig.Exchange(context.Background(), code) //kodu erişim tokenına dönüştürür.
	if err != nil {
		fmt.Printf("oauthConf.Exchange() failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	//Erişim tokenını kullanarak Google OAuth2 API'sinden kullanıcı bilgilerini almak.
	resp, err := http.Get(fmt.Sprintf("https://www.googleapis.com/oauth2/v2/userinfo?access_token=%s", token.AccessToken))
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil { //alınan yanıtı googleUser struct'ına dönüştürmek.
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var userID int
	err = utils.Db.QueryRow("SELECT id FROM users WHERE email = ?", googleUser.Email).Scan(&userID)
	if err != nil && err != sql.ErrNoRows {
		fmt.Printf("Error querying user: %v", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if value == "GoogleLogin" {
		if userID == 0 {
			utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
				"LoginErrorMsg": "Email not registered. Please register first.",
			})
			return
		}
	} else if value == "GoogleRegister" {
		if userID != 0 {
			utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
				"RegisterErrorMsg": "Email already registered",
			})
			return
		}

		username := googleUser.Name
		// Aynı kullanıcı adını kontrol et
		for {
			var existingUserID int
			err = utils.Db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&existingUserID)
			if err == sql.ErrNoRows {
				break
			}
			if err != nil {
				fmt.Printf("Error checking existing username: %v", err)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
			// Rastgele sayı ekleyerek kullanıcı adını değiştir
			username, err = generateRandomUsername(googleUser.Name)
			if err != nil {
				fmt.Printf("Error generating random username: %v", err)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
		}

		utils.RenderTemplate(w, "templates/username_conflict.html", map[string]interface{}{
			"BaseUsername":      googleUser.Name,
			"SuggestedUsername": username,
			"Email":             googleUser.Email,
			"IconURL":           googleUser.Picture,
		})
		return
	}

	sessionToken := utils.GenerateSessionToken()
	expiration := time.Now().Add(24 * time.Hour)

	_, err = utils.Db.Exec("UPDATE users SET session_token = ?, token_expires = ? WHERE id = ?", sessionToken, expiration, userID)
	if err != nil {
		http.Error(w, "Failed to update session token.", http.StatusInternalServerError)
		return
	}
	//Kullanıcının kimliğini doğrulamak ve kullanıcının oturumunun süresini yönetmek için, (cookie)
	utils.SetLoginCookie(w, userID, sessionToken, int(time.Until(expiration).Seconds()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func generateNonce() string {
	b := make([]byte, 16) // 128-bit
	_, err := rand.Read(b)
	if err != nil {
		fmt.Printf("Failed to generate nonce: %v", err)
	}
	return hex.EncodeToString(b)
}

func handleConfirmUsername(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	iconURL := r.FormValue("icon_url")

	var existingUserID int
	err := utils.Db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&existingUserID)
	if err == nil {
		http.Error(w, "Username is already taken, please choose a different one.", http.StatusBadRequest)
		return
	} else if err != sql.ErrNoRows {
		http.Error(w, fmt.Sprintf("Error checking username: %v", err), http.StatusInternalServerError)
		return
	}

	_, err = utils.Db.Exec("INSERT INTO users (username, email, usericon_url) VALUES (?, ?, ?)", username, email, iconURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error registering user: %v", err), http.StatusInternalServerError)
		return
	}

	var userID int
	err = utils.Db.QueryRow("SELECT id FROM users WHERE email = ?", email).Scan(&userID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching new user ID: %v", err), http.StatusInternalServerError)
		return
	}
	//Kullanıcı oturum tokenı oluşturmak ve bu tokenı veritabanına eklemek.
	sessionToken := utils.GenerateSessionToken()
	expiration := time.Now().Add(24 * time.Hour)

	_, err = utils.Db.Exec("UPDATE users SET session_token = ?, token_expires = ? WHERE id = ?", sessionToken, expiration, userID)
	if err != nil {
		http.Error(w, "Failed to update session token.", http.StatusInternalServerError)
		return
	}
	//kullanıcının kimliğini doğrulamak ve kullanıcının oturumunun süresini yönetmektir.
	utils.SetLoginCookie(w, userID, sessionToken, int(time.Until(expiration).Seconds()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func generateRandomUsername(baseUsername string) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return "", fmt.Errorf("failed to generate random number: %v", err)
	}
	return fmt.Sprintf("%s%d", baseUsername, n.Int64()), nil
}

func handleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	oauthStateStringGitHub = generateNonce() + ":GitHubLogin" //kimlik doğrulama işlemi ,state
	url := githubOauthConfig.AuthCodeURL(oauthStateStringGitHub, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect) //yetkilendirme URL'sine yönlendir
}

func handleGitHubRegister(w http.ResponseWriter, r *http.Request) {
	oauthStateStringGitHub = generateNonce() + ":GitHubRegister"
	url := githubOauthConfig.AuthCodeURL(oauthStateStringGitHub, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state") //güvenliği artırmak
	stateParts := strings.Split(state, ":")
	if len(stateParts) != 2 || stateParts[0] != strings.Split(oauthStateStringGitHub, ":")[0] {
		log.Printf("Invalid state: %s", state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	value := stateParts[1]
	//Google tarafından geri yönlendirilen URL'den code parametresini alır.
	code := r.FormValue("code")
	token, err := githubOauthConfig.Exchange(context.Background(), code) //kodu erişim tokenına dönüştürür.
	if err != nil {
		log.Printf("oauthConfGitHub.Exchange() failed with '%s'", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	client := githubOauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		log.Printf("Failed to fetch user data: %v", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	var githubUser struct {
		ID      int    `json:"id"`
		Email   string `json:"email"`
		Login   string `json:"login"` // Değişiklik burada: Name yerine Login kullanılıyor
		Picture string `json:"avatar_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&githubUser); err != nil {
		log.Printf("Failed to decode user data: %v", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if githubUser.Email == "" {
		resp, err := client.Get("https://api.github.com/user/emails")
		if err != nil {
			log.Printf("Failed to fetch user emails: %v", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		defer resp.Body.Close()

		var emails []struct {
			Email   string `json:"email"`
			Primary bool   `json:"primary"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
			log.Printf("Failed to decode user emails: %v", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		for _, email := range emails {
			if email.Primary {
				githubUser.Email = email.Email
				break
			}
		}
	}

	if githubUser.Email == "" {
		http.Error(w, "Unable to fetch email from GitHub", http.StatusInternalServerError)
		return
	}

	var userID int
	err = utils.Db.QueryRow("SELECT id FROM users WHERE email = ?", githubUser.Email).Scan(&userID)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Error querying user: %v", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if value == "GitHubLogin" {
		if userID == 0 {
			utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
				"LoginErrorMsg": "Email not registered. Please register first.",
			})
			return
		}
	} else if value == "GitHubRegister" {
		if userID != 0 {
			utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
				"RegisterErrorMsg": "Email already registered",
			})
			return
		}

		username := githubUser.Login
		var existingUserID int
		err = utils.Db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&existingUserID)
		if err == sql.ErrNoRows {
			// Kullanıcı adı mevcut değil, doğrudan devam et
			_, err = utils.Db.Exec("INSERT INTO users (username, email, usericon_url) VALUES (?, ?, ?)", username, githubUser.Email, githubUser.Picture)
			if err != nil {
				log.Printf("Error registering user: %v", err)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
			err = utils.Db.QueryRow("SELECT id FROM users WHERE email = ?", githubUser.Email).Scan(&userID)
			if err != nil {
				log.Printf("Error fetching new user ID: %v", err)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
		} else if err != nil {
			log.Printf("Error checking existing username: %v", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		} else {
			// Kullanıcı adı zaten var, kullanıcıya yeni bir kullanıcı adı öner
			for {
				username, err = generateRandomUsername(githubUser.Login)
				if err != nil {
					log.Printf("Error generating random username: %v", err)
					http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
					return
				}

				err = utils.Db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&existingUserID)
				if err == sql.ErrNoRows {
					break
				}
				if err != nil {
					log.Printf("Error checking existing username: %v", err)
					http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
					return
				}
			}

			utils.RenderTemplate(w, "templates/username_conflict.html", map[string]interface{}{
				"BaseUsername":      githubUser.Login,
				"SuggestedUsername": username,
				"Email":             githubUser.Email,
				"IconURL":           githubUser.Picture,
			})
			return // Kullanıcı adı çatışması olduğunda geri dön
		}
	}

	sessionToken := utils.GenerateSessionToken()
	expiration := time.Now().Add(24 * time.Hour)

	_, err = utils.Db.Exec("UPDATE users SET session_token = ?, token_expires = ? WHERE id = ?", sessionToken, expiration, userID)
	if err != nil {
		log.Printf("Failed to update session token: %v", err)
		http.Error(w, "Failed to update session token.", http.StatusInternalServerError)
		return
	}

	utils.SetLoginCookie(w, userID, sessionToken, int(time.Until(expiration).Seconds()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleFacebookLogin(w http.ResponseWriter, r *http.Request) {
	facebookOauthStateString = generateNonce() + ":FacebookLogin"
	url := facebookOauthConfig.AuthCodeURL(facebookOauthStateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleFacebookRegister(w http.ResponseWriter, r *http.Request) {
	facebookOauthStateString = generateNonce() + ":FacebookRegister"
	url := facebookOauthConfig.AuthCodeURL(facebookOauthStateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleFacebookCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	stateParts := strings.Split(state, ":")
	if len(stateParts) != 2 || stateParts[0] != strings.Split(facebookOauthStateString, ":")[0] {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	value := stateParts[1]

	code := r.FormValue("code")
	token, err := facebookOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	resp, err := http.Get(fmt.Sprintf("https://graph.facebook.com/me?access_token=%s&fields=id,name,email,picture.type(large)", token.AccessToken))
	if err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	var facebookUser struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&facebookUser); err != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var userID int
	err = utils.Db.QueryRow("SELECT id FROM users WHERE email = ?", facebookUser.Email).Scan(&userID)
	if err != nil && err != sql.ErrNoRows {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	if value == "FacebookLogin" {
		if userID == 0 {
			utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
				"LoginErrorMsg": "Email not registered. Please register first.",
			})
			return
		}
	} else if value == "FacebookRegister" {
		if userID != 0 {
			utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
				"RegisterErrorMsg": "Email already registered",
			})
			return
		}
		_, err = utils.Db.Exec("INSERT INTO users (username, email, usericon_url) VALUES (?, ?, ?)", facebookUser.Name, facebookUser.Email, facebookUser.Picture.Data.URL)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		err = utils.Db.QueryRow("SELECT id FROM users WHERE email = ?", facebookUser.Email).Scan(&userID)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
	}

	sessionToken := utils.GenerateSessionToken()
	expiration := time.Now().Add(24 * time.Hour)
	_, err = utils.Db.Exec("UPDATE users SET session_token = ?, token_expires = ? WHERE id = ?", sessionToken, expiration, userID)
	if err != nil {
		http.Error(w, "Failed to update session token.", http.StatusInternalServerError)
		return
	}

	utils.SetLoginCookie(w, userID, sessionToken, int(time.Until(expiration).Seconds()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")

	if r.Method == http.MethodGet {
		utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
			"Redirect": redirect,
		})
		return
	}

	if r.Method != http.MethodPost {
		utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
			"LoginErrorMsg": "Invalid request method",
		})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" && password == "" {
		handleGitHubLogin(w, r)
		return
	}

	if email == "" && password == "" {
		handleFacebookLogin(w, r)
		return
	}

	var dbEmail, dbPassword string
	var userID int
	err := utils.Db.QueryRow("SELECT id, email, password FROM users WHERE email = ?", email).Scan(&userID, &dbEmail, &dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
				"LoginErrorMsg": "User not found",
				"Redirect":      redirect,
			})
			return
		}
		utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
			"LoginErrorMsg": fmt.Sprintf("Error querying user: %v", err),
			"Redirect":      redirect,
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
	if err != nil {
		utils.RenderTemplate(w, "templates/login.html", map[string]interface{}{
			"LoginErrorMsg": "Invalid email or password",
			"Redirect":      redirect,
		})
		return
	}

	sessionToken := utils.GenerateSessionToken()
	expiration := time.Now().Add(24 * time.Hour)

	_, err = utils.Db.Exec("UPDATE users SET session_token = ?, token_expires = ? WHERE id = ?", sessionToken, expiration, userID)
	if err != nil {
		http.Error(w, "Failed to update session token.", http.StatusInternalServerError)
		return
	}

	utils.SetLoginCookie(w, userID, sessionToken, int(time.Until(expiration).Seconds()))

	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		utils.RenderTemplate(w, "templates/register.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirmPassword")

	// GitHub ile kayıt olma işlemi
	if email == "" && password == "" {
		handleGitHubLogin(w, r)
		return
	}

	// Facebook ile kayıt olma işlemi
	if email == "" && password == "" {
		handleFacebookLogin(w, r)
		return
	}

	if password != confirmPassword {
		utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
			"RegisterErrorMsg": "Passwords do not match",
			"Username":         username,
			"Email":            email,
		})
		return
	}

	emailRegex := `^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`
	matched, err := regexp.MatchString(emailRegex, email)
	if err != nil || !matched {
		utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
			"RegisterErrorMsg": "Invalid email format",
			"Username":         username,
			"Email":            email,
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
			"RegisterErrorMsg": fmt.Sprintf("Error hashing password: %v", err),
			"Username":         username,
			"Email":            email,
		})
		return
	}

	_, err = utils.Db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", username, email, string(hashedPassword))
	if err != nil {
		utils.RenderTemplate(w, "templates/register.html", map[string]interface{}{
			"RegisterErrorMsg": fmt.Sprintf("Error registering user: %v", err),
			"Username":         username,
			"Email":            email,
		})
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	userid, err := utils.GetUserIDFromCookie(r)
	if err != nil {
		log.Println(err)
	}
	utils.SetLoginCookie(w, userid, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
