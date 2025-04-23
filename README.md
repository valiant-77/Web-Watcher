# WebWatcher

A full stack web application for monitoring websites for specific keywords with user authentication, automated scanning, and email notifications.

## Features

* **User Authentication**: Secure registration and login system
* **Watchlist Management**: Create and manage keywords and URLs to monitor
* **Automated Scanning**: Scheduled website scanning every 6 hours
* **Manual Scanning**: Trigger immediate scans (limited to 4 per day)
* **Match Tracking**: View and manage detected keyword matches
* **Email Notifications**: Receive alerts when keywords are found
* **Feedback System**: Submit feedback directly to developers

## Technologies Used

### Backend
* Node.js
* Express.js
* MongoDB (with Mongoose)
* JWT for authentication
* Bcrypt for password hashing
* Axios and Cheerio for web scraping
* Node-cron for scheduled tasks
* Nodemailer for email notifications

### Frontend
* HTML, CSS(Tailwind CSS), JavaScript
* Frontend code is served statically from the server

## Installation and Setup

1. **Clone the repository**
   ```
   git clone https://github.com/yourusername/web-watcher.git
   ```

   ```
   cd web-watcher
   ```

2. **Install dependencies**
   ```
   npm install
   ```

3. **Create a .env file in the root directory with the following variables**
   ```
   PORT=3000
   MONGODB_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret_key
   EMAIL_USER=your_email@gmail.com
   EMAIL_PASSWORD=your_email_app_password
   FEEDBACK_EMAIL=email_to_receive_feedback
   ```

4. **Start the server**
   ```
   npm start
   ```

5. **Access the application**
   Open your browser and navigate to `http://localhost:3000`


## Project Structure

The server handles web scraping, data storage, user authentication, and API endpoints. The web scraper automatically runs every 6 hours and scans specified URLs for keywords, storing results and sending email notifications when matches are found.

## Contact

Aditya TG - adityagirish812@gmail.com

