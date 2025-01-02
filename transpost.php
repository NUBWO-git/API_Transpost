<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");

// จัดการคำขอ OPTIONS (สำหรับ CORS)
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
   http_response_code(200);
   exit();
}

require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

session_start();

// ฟังก์ชันเชื่อมต่อฐานข้อมูล
function connectDatabase()
{
   $servername = "localhost";
   $username = "root";
   $password = "";
   $dbname = "transpost";

   $conn = new mysqli($servername, $username, $password, $dbname);
   if ($conn->connect_error) {
      responseError("ไม่สามารถเชื่อมต่อฐานข้อมูลได้: " . $conn->connect_error);
   }
   return $conn;
}

// ฟังก์ชันตอบกลับแบบ JSON
function responseJson($status, $message, $data = null)
{
   header('Content-Type: application/json');
   $response = [
      "status" => $status,
      "message" => $message
   ];
   if ($data !== null) {
      $response["data"] = $data;
   }
   echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
   exit();
}

// ฟังก์ชันตอบกลับเมื่อเกิดข้อผิดพลาด
function responseError($message)
{
   responseJson("error", $message);
}

// ฟังก์ชันส่ง OTP ด้วย PHPMailer
function sendOtpEmail($email, $otp)
{
   $mail = new PHPMailer(true);
   try {
      $mail->isSMTP();
      $mail->Host = 'smtp.gmail.com';
      $mail->SMTPAuth = true;
      $mail->Username = 'motobikerental64@gmail.com'; // อีเมลของคุณ
      $mail->Password = 'jvle brai erfi zgpi'; // ใช้ App Password ที่สร้างไว้
      $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
      $mail->Port = 587;

      $mail->setFrom('motobikerental64@gmail.com', 'Transpost');
      $mail->addAddress($email);
      $mail->Subject = 'Your OTP Code';
      $mail->isHTML(true);
      $mail->Body = "
            <html>
               <head>
                  <style>
                     body { font-family: Arial, sans-serif; color: #000; }
                     .otp { font-size: 24px; font-weight: bold; color: #007BFF; }
                  </style>
               </head>
               <body>
                  <p>สวัสดีครับ/ค่ะ,</p>
                  <p>ขอบคุณที่สมัครใช้งานกับ Transpost กรุณากรอกรหัส OTP ด้านล่าง:</p>
                  <p><span class='otp'>OTP ของคุณคือ: $otp</span></p>
                  <p>OTP มีอายุ 1 นาที</p>
                  <p>ขอบคุณครับ/ค่ะ,</p>
                  <p>ทีมงาน Transpost</p>
               </body>
            </html>";

      $mail->send();
      return true;
   } catch (Exception $e) {
      return $mail->ErrorInfo;
   }
}

// สร้าง OTP และเก็บใน session
function generateAndStoreOtp($expirySeconds = 60)
{
   $otp = mt_rand(100000, 999999); // สร้าง OTP แบบสุ่ม
   $_SESSION['otp'] = $otp;
   $_SESSION['otp_created_at'] = time();  // เก็บเวลาที่ OTP ถูกสร้าง
   $_SESSION['otp_expiry'] = $expirySeconds;  // กำหนดเวลาหมดอายุของ OTP (ในที่นี้คือ 60 วินาที)
   return $otp;
}

// ฟังก์ชันตรวจสอบ OTP
// ฟังก์ชันตรวจสอบ OTP
function verifyOtp($inputOtp)
{
   if (!isset($_SESSION['otp']) || !isset($_SESSION['otp_created_at'])) {
      responseError("ไม่มี OTP ในระบบ หรือ OTP หมดอายุแล้ว");
   }

   // ตรวจสอบเวลาหมดอายุ
   if (time() - $_SESSION['otp_created_at'] > $_SESSION['otp_expiry']) {
      unset($_SESSION['otp'], $_SESSION['otp_created_at'], $_SESSION['otp_expiry']);
      responseError("OTP หมดอายุ");
   }

   // ตรวจสอบ OTP
   if ($inputOtp != $_SESSION['otp']) {
      responseError("OTP ไม่ถูกต้อง");
   }

   // เคลียร์ OTP หลังจากตรวจสอบ
   unset($_SESSION['otp'], $_SESSION['otp_created_at'], $_SESSION['otp_expiry']);
   return true;
}


// รับข้อมูล JSON
$data = json_decode(file_get_contents("php://input"), true);

// ตรวจสอบคำขอว่าเป็น POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
   responseError("คำขอต้องเป็น POST เท่านั้น");
}

// ตรวจสอบ action
if (!isset($data['action'])) {
   responseError("กรุณาระบุ action");
}

$action = $data['action'];

switch ($action) {
   case 'sendOtp':
      // ตรวจสอบข้อมูลที่จำเป็น
      if (!isset($data['username']) || empty(trim($data['username']))) {
         responseError("กรุณากรอกชื่อผู้ใช้");
      }

      if (!isset($data['email']) || empty(trim($data['email']))) {
         responseError("กรุณากรอกอีเมล");
      }

      if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
         responseError("รูปแบบอีเมลไม่ถูกต้อง");
      }

      if (!isset($data['password']) || empty(trim($data['password']))) {
         responseError("กรุณากรอกรหัสผ่าน");
      }

      // ตรวจสอบอีเมลซ้ำ
   /*
      $conn = connectDatabase();
      $checkEmail = $conn->prepare("SELECT * FROM user_transpost WHERE email = ?");
      $checkEmail->bind_param("s", $data['email']);
      $checkEmail->execute();
      $result = $checkEmail->get_result();
      if ($result->num_rows > 0) {
         responseError("อีเมลนี้ถูกใช้ไปแล้ว");
      }
      $conn->close();
   */
      // ป้องกันการส่ง OTP ซ้ำ
      if (isset($_SESSION['otp_last_sent']) && (time() - $_SESSION['otp_last_sent']) < 60) {
         responseError("กรุณารอ 1 นาทีก่อนขอ OTP ใหม่");
      }
      $_SESSION['otp_last_sent'] = time();

      // สร้าง OTP
      $otp = generateAndStoreOtp();

      // ส่ง OTP
      $emailStatus = sendOtpEmail($data['email'], $otp);

      if ($emailStatus === true) {
         responseJson("success", "OTP ถูกส่งไปยังอีเมล");
      } else {
         responseError("ไม่สามารถส่ง OTP ได้: " . $emailStatus);
      }
      break;

      case 'verifyOtp':
         // ตรวจสอบข้อมูลที่จำเป็น
         if (!isset($data['otp']) || empty(trim($data['otp']))) {
            responseError("กรุณากรอก OTP");
         }
      
         if (!isset($data['username']) || empty(trim($data['username']))) {
            responseError("กรุณากรอกชื่อผู้ใช้");
         }
      
         if (!isset($data['email']) || empty(trim($data['email']))) {
            responseError("กรุณากรอกอีเมล");
         }
      
         if (!isset($data['password']) || empty(trim($data['password']))) {
            responseError("กรุณากรอกรหัสผ่าน");
         }
      
         // รับค่าจากผู้ใช้
         $otp = trim($data['otp']);
         $username = trim($data['username']);
         $email = trim($data['email']);
         $password = trim($data['password']);
      
         // ตรวจสอบ OTP
         $otpValid = verifyOtp($otp);
      
         if ($otpValid) {
            // เชื่อมต่อกับฐานข้อมูล
            $conn = connectDatabase();
      
            // **คอมเมนต์ส่วนนี้ออก** เพื่อไม่ตรวจสอบอีเมลซ้ำ
            /*
            $checkEmail = $conn->prepare("SELECT * FROM user_transpost WHERE email = ?");
            $checkEmail->bind_param("s", $email);
            $checkEmail->execute();
            $result = $checkEmail->get_result();
            if ($result->num_rows > 0) {
               responseError("อีเมลนี้ถูกใช้ไปแล้ว");
            }
            */
      
            // เข้ารหัสรหัสผ่าน
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
      
            // บันทึกข้อมูลผู้ใช้ลงในฐานข้อมูล
            $stmt = $conn->prepare("INSERT INTO user_transpost (username, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $email, $hashedPassword);
      
            if ($stmt->execute()) {
               responseJson("success", "สมัครสมาชิกสำเร็จ");
            } else {
               responseError("ไม่สามารถบันทึกข้อมูลได้: " . $stmt->error);
            }
      
            // ปิดการเชื่อมต่อฐานข้อมูล
            $stmt->close();
            $conn->close();
         } else {
            responseError("OTP ไม่ถูกต้อง");
         }
         break;           

   default:
      responseError("action ไม่ถูกต้อง");
}
