# Intelli-Team-Collaborators-
This is a team collaboration on Sellust Multi Vendor Marketplace project for both front-end and back-end development... 


## Getting Started

## create .env at the root folder

## port and mongourl
PORT=
MONGO_URI=""

## jwt secret and expire time
JWT_SECRET=""
LASTING="

## node mailer
EMAIL=
SENDERMAIL=
PASSWORD=

## then

## npm install
## npm start



## register user
http://localhost:4000/api/v1/user/register

req.post = 
{
    "id": "64708d0f2de47643e24da7fa",
    "fname": "Mohammed",
    "lname": "Abdulsalam",
    "phone":"000939393",
    "email": "devabdulsalam0@gmail.com",
    "password" : "ii898W98YUFwe8@m",
    "state":"Kano state",
    "city":"Kano metropolice",
    "country":"64170496ef1cc85d8429522b"
}

## login user
http://localhost:4000/api/v1/user/login

req.post = 
{
    "phone":"000939393",
    "email": "devabdulsalam0@gmail.com",
    "password" : "ii898W98YUFwe8@m",
}
 res ={
    "user": {
        "id": "6470d9f6cb88367d89f140ae",
        "fname": "Mohammed",
        "lname": "Abdulsalam",
        "email": "devabdulsalam0@gmail.com",
        "role": "user",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0NzBkOWY2Y2I4ODM2N2Q4OWYxNDBhZSIsImVtYWlsIjoiZGV2YWJkdWxzYWxhbTBAZ21haWwuY29tIiwiaWF0IjoxNjg1MTE3OTA2LCJleHAiOjE2ODUyOTA3MDZ9.zSmg0fniLurwOWyKwCxD1WNWKkUGyImzpOIVFPPQr3o",
        "msg": "logged in successful"
    }
}
## send otp
http://localhost:4000/api/v1/user/send

req.post = {
    email: "abcd@gmai.com"
}
res = {
    "status": "PENDING",
    "msg": "Verication OTP sent to Email"
}

## verify user throuhg otp 
http://localhost:4000/api/v1/user/send

req.post = {
    otp: "9009"
    email: "abcd@gmai.com"
}
res = {
    msg: 'User Verified!',
    "token": "90909",
}


## forget password
http://localhost:4000/api/v1/user/forget_password

req.post = 
{
    "email": "devabdulsalam74@gmail.com",
}

res ={
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY0NzBkOWY2Y2I4ODM2N2Q4OWYxNDBhZSIsImVtYWlsIjoiZGV2YWJkdWxzYWxhbTBAZ21haWwuY29tIiwiaWF0IjoxNjg1MTE4MDIxLCJleHAiOjE2ODUyOTA4MjF9.q9YvY2TfF6pt5_NHMzE1I3EBMEC7N03gS0ZxjlUB1QU",
    "info": {
        "accepted": [
            "devabdulsalam74@gmail.com"
        ],
        "rejected": [],
        "ehlo": [
            "SIZE 35882577",
            "8BITMIME",
            "AUTH LOGIN PLAIN XOAUTH2 PLAIN-CLIENTTOKEN OAUTHBEARER XOAUTH",
            "ENHANCEDSTATUSCODES",
            "PIPELINING",
            "CHUNKING",
            "SMTPUTF8"
        ],
        "envelopeTime": 1058,
        "messageTime": 854,
        "messageSize": 1262,
        "response": "250 2.0.0 OK  1685118025 q25-20020a7bce99000000b003f4268f51f5sm5731363wmj.0 - gsmtp",
        "envelope": {
            "from": "ammuftau74@gmail.com",
            "to": [
                "devabdulsalam74@gmail.com"
            ]
        },
        "messageId": "<461f599b-c8b6-29da-4f69-26ff9905a61a@gmail.com>"
    },
    "message": "Password reset link sent successfully"
}

## reset password
link sent to the mail
req.get http://localhost:4000/api/v1/user/reset_password/id/token


## change password
http://localhost:4000/api/v1/user/change_password
req.postt = {
    "email": "devabdulsalam74@gmail.com",
    "password" : "ii898W98YUFwe8@m",
    "confirmPassword" : "ii898W98YUFwe@m",
    "token": "tok8989en"
}


## update user
http://localhost:4000/api/v1/user/update

req.put = formData



## get all users
http://localhost:4000/api/v1/user
res =[{
        "_id": "647082441868609d730d47f7",
        "fname": "Mohammed",
        "lname": "Abdulsalamm",
        "email": "devabdulsalam700@gmail.com",
        "role": "user",
        "password": "$2a$10$9fd9eoHGhJQM8szBKwlSU.qH8wCpdQBaWOTN.Bjgsv4bxdLYiRIDu",
        "state": "Kano state",
        "country": "64170496ef1cc85d8429522b",
        "createdAt": "2023-05-26T09:56:21.045Z",
        "updatedAt": "2023-05-26T15:02:26.565Z",
        "__v": 0,
        "city": "Kano metropolise"
    },
    {
        "_id": "647082441868609d730d47f7",
        "fname": "Mohammed",
        "lname": "Abdulsalamm",
        "email": "devabdulsalam700@gmail.com",
        "role": "user",
        "password": "$2a$10$9fd9eoHGhJQM8szBKwlSU.qH8wCpdQBaWOTN.Bjgsv4bxdLYiRIDu",
        "state": "Kano state",
        "country": "64170496ef1cc85d8429522b",
        "createdAt": "2023-05-26T09:56:21.045Z",
        "updatedAt": "2023-05-26T15:02:26.565Z",
        "__v": 0,
        "city": "Kano metropolise"
    },
]