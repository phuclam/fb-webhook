'use strict';

require('dotenv').config();
const bodyParser = require('body-parser'),
    crypto = require('crypto'),
    express = require('express'),
    https = require('https'),
    request = require('request'),
    fs = require('fs'),
    uuid = require('uuid/v4'),
    mongoose = require('mongoose'),
    mongoosePaginate = require('mongoose-paginate'),
    md5 = require('md5'),
    ChatSDK = require('@livechat/chat-sdk');

// Origin
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN;
const SERVER_URL = process.env.SERVER_URL;
const VALIDATION_KEY = 'arzqvfom4121xv9vidfp';
const ADMIN_NAME = 'Admin';
const ADMIN_ID = 'owner';

// Facebook
const APP_SECRET = process.env.FB_APP_SECRET;
const VALIDATION_TOKEN = process.env.FB_VALIDATE_TOKEN;
const PAGE_ACCESS_TOKEN = process.env.FB_PAGE_ACCESS_TOKEN;

// Line
const LINE_ACCESS_TOKEN = process.env.LINE_ACCESS_TOKEN;
const LINE_CHANNEL_SECRET = process.env.LINE_CHANNEL_SECRET;

// LiveChat
const LIVECHAT_CLIENT_ID = process.env.LIVECHAT_CLIENT_ID;
const LIVECHAT_CLIENT_SECRET = process.env.LIVECHAT_CLIENT_SECRET;
const LIVECHAT_CONFIG_FILE = 'livechat.json';

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL && ALLOW_ORIGIN
    && LINE_ACCESS_TOKEN && LINE_CHANNEL_SECRET
    && LIVECHAT_CLIENT_ID && LIVECHAT_CLIENT_SECRET)) {
    console.error("Missing config values");
    process.exit(1);
}

var app = express();
var server = app.listen(5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({verify: verifyRequestSignature}));
app.use(express.static('public'));
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", ALLOW_ORIGIN);
    res.header("Access-Control-Allow-Headers", "X-Requested-With");
    res.header("Access-Control-Allow-Headers", "Content-Type");
    res.header("Access-Control-Allow-Methods", "PUT, GET, POST, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Credentials", true);
    next();
});
//Socket.io
const io = require('socket.io').listen(server);
var messageSchema = mongoose.Schema({
    sender_id: String,
    recipient_id: String,
    type: String,
    message_id: {type: String, default: uuid()},
    message_text: String,
    attachments: Array,
    created: {type: Date, default: Date.now},
}).plugin(mongoosePaginate);

var recipientSchema = mongoose.Schema({
    recipient_id: {type: String, unique: true},
    recipient_name: String,
    type: String,
    live_chat_id: {type: String, unique: true},
    live_customer_id: String,
    last_message: {type: Date, default: Date.now}
}).plugin(mongoosePaginate);

var Message = mongoose.model('messages', messageSchema);
var Recipient = mongoose.model('recipients', recipientSchema);

//Live chat
const chatSDK = new ChatSDK({debug: true});

/*
//secret: f6b3d6e6f93d3b2200ad11b3d13db1e9
 https://accounts.livechatinc.com/
 ?response_type=code
 &client_id=37f247f1a7431256bda730b0264f049c
 &redirect_uri=http://localhost:5000/live-chat-verify


 https://accounts.livechatinc.com/
 ?response_type=code
 &client_id=37f247f1a7431256bda730b0264f049c
 &redirect_uri=https://kycdev.bittenet.com/live-chat-verify

*/

mongoose.Promise = require('bluebird');
mongoose.connect(process.env.MONGO_CONNECTION_STRING, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
    useCreateIndex: true
}, function (err) {
    if (err) {
        throw err;
    }

    io.on('connection', (socket) => {
        console.log('A new Client has just been connected');
        socket.on('disconnect', () => console.log('Client disconnected'));
        //Send message
        socket.on('sendMessage', function (type, recipientId, messageText) {
            if (type === 'Facebook') {
                sendTextMessage(recipientId, messageText);
            } else if (type === 'Line') {
                sendLineTextMessage(recipientId, messageText);
            } else if (type === 'LiveChat') {
                sendLiveChatTextMessage(recipientId, messageText).then(function () {
                    //do nothing.
                });
            }
        });
        //Send attachment from url
        socket.on('sendAttachment', function (type, recipientId, fileType, url, previewUrl) {
            if (type === 'Line') {
                sendLineImage(recipientId, url, previewUrl);
            } else if (type === 'Facebook') {
                sendAttachment(recipientId, url, fileType);
            } else if (type === 'LiveChat') {
                sendLiveChatFileMessage(recipientId, url).then(function () {
                    //do nothing
                });
            }
        });
        //Mark as seen
        socket.on('seen', function (recipientId) {
            sendMarkSeen(recipientId);
        });
        //Update Status / Assigned to
        socket.on('updateAssignedStatus', function (recipientId, data) {
            io.emit('updateAssignedStatus', recipientId, data);
        })
    });

    /**
     * Line Webhook
     */

    app.post('/line-webhook', function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }
        var data = req.body;
        data.events.forEach(function (entry) {
            if (entry.type === 'message') {
                receivedLineMessage(entry);
            }
        });
        res.sendStatus(200);
    });

    app.post('/api/conversations', async function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }

        const resPerPage = parseInt(req.query.limit) || 15;
        const page = parseInt(req.query.page) || 1;
        try {
            let output = [];
            let next;
            if (req.query.recipient) {
                const recipient = await Recipient.findOne({recipient_id: req.query.recipient});
                let msg = await Message.findOne({recipient_id: recipient.recipient_id}).sort('-created');
                let message = {};
                if (msg) {
                    message = {
                        type: msg.type,
                        text: msg.type === 'text' ? msg.message_text : '(' + msg.type + ')',
                        created: msg.created
                    }
                }
                output.push({
                    id: recipient.recipient_id,
                    name: recipient.recipient_name,
                    updated_time: recipient.last_message,
                    type: recipient.type,
                    message: message
                });
                next = '';
            } else {
                const recipients = await Recipient.find()
                    .sort('-last_message')
                    .skip((resPerPage * page) - resPerPage)
                    .limit(resPerPage);
                const count = await Recipient.estimatedDocumentCount();
                const max = Math.ceil(count / resPerPage);

                for (const recipient of recipients) {
                    let msg = await Message.findOne({recipient_id: recipient.recipient_id}).sort('-created');
                    let message = {};
                    if (msg) {
                        message = {
                            type: msg.type,
                            text: msg.type === 'text' ? msg.message_text : '(' + msg.type + ')',
                            created: msg.created
                        }
                    }
                    output.push({
                        id: recipient.recipient_id,
                        name: recipient.recipient_name,
                        updated_time: recipient.last_message,
                        type: recipient.type,
                        message: message
                    });
                }
                next = (page + 1) <= max ? (page + 1) : ''
            }

            res.json({
                data: output,
                next: next,
            });
        } catch (err) {
            throw new Error(err);
        }
    });

    app.post('/api/messages', async function (req, res) {
        if (!res.signature_matched) {
            return res.sendStatus(403);
        }

        const resPerPage = parseInt(req.query.limit) || 15;
        const page = parseInt(req.query.page) || 1;
        const recipientId = req.query.recipient;

        try {
            const messages = await Message.find({recipient_id: recipientId})
                .sort('-created')
                .skip((resPerPage * page) - resPerPage)
                .limit(resPerPage);
            const count = await Message.find({recipient_id: recipientId}).countDocuments();
            const max = Math.ceil(count / resPerPage);

            res.json({
                data: messages,
                next: (page + 1) <= max ? (page + 1) : '',
            });
        } catch (err) {
            throw new Error(err);
        }
    })

    /**
     * Live Chat Webhook
     */

    app.get('/live-chat-verify', function (req, res) {
        const code = req.query.code;
        request({
            url: 'https://accounts.livechatinc.com/token',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                grant_type: "authorization_code",
                code: code,
                client_id: LIVECHAT_CLIENT_ID,
                client_secret: LIVECHAT_CLIENT_SECRET,
                redirect_uri: SERVER_URL + '/live-chat-verify'
            })
        }, function (error, response, body) {
            if (!error && response.statusCode === 200) {
                fs.writeFileSync(LIVECHAT_CONFIG_FILE, body);
                refreshLiveChatToken().then((data) => {
                    chatSDK.init({
                        access_token: data.access_token
                    });
                })
                res.sendStatus(200);
            } else {
                res.sendStatus(500);
            }
        });
    });

    chatSDK.on('incoming_chat_thread', (data) => {
        if (data.payload.chat.users[0]) {
            let recipient = data.payload.chat.users[0];
            Recipient.findOneAndUpdate(
                {recipient_id: md5(recipient.email.toLowerCase())},
                {
                    recipient_name: recipient.name,
                    type: 'LiveChat',
                    live_chat_id: data.payload.chat.id,
                    live_customer_id: recipient.id,
                    last_message: new Date()
                },
                {upsert: true, new: true, setDefaultsOnInsert: true},
                function (error) {
                    //do nothing
                });
        }
    });

    chatSDK.on('incoming_event', (data) => {
        let event = data.payload.event;
        let chatId = data.payload.chat_id;
        let attachmentSave, attachmentSend;
        switch (event.type) {
            case "message":
                Recipient.findOneAndUpdate(
                    {live_chat_id: chatId},
                    {
                        last_message: new Date(),
                    },
                    {upsert: true, new: true, setDefaultsOnInsert: true},
                    function (error, res) {
                        if (!error) {
                            if (res.live_customer_id === event.author_id) {
                                let msg = new Message({
                                    sender_id: res.recipient_id,
                                    recipient_id: res.recipient_id,
                                    type: 'text',
                                    message_id: event.id,
                                    message_text: event.text
                                });
                                msg.save(function (err, data) {
                                    if (!err) {
                                        let obj = {
                                            from: {
                                                name: res.recipient_name,
                                                id: res.recipient_id,
                                            },
                                            message: data.message_text,
                                            id: data.message_id,
                                            created_time: data.created
                                        };
                                        io.emit('receivedMessage', res.recipient_id, JSON.stringify(obj), false);
                                    }
                                });
                            } else {
                                let msg = new Message({
                                    sender_id: ADMIN_ID,
                                    recipient_id: res.recipient_id,
                                    type: 'text',
                                    message_text: event.text
                                });
                                msg.save(function (err, data) {
                                    if (!err) {
                                        let obj = {
                                            from: {
                                                name: ADMIN_NAME,
                                                id: ADMIN_ID,
                                            },
                                            message: data.message_text,
                                            id: data.message_id,
                                            created_time: data.created
                                        };
                                        io.emit('receivedMessage', res.recipient_id, JSON.stringify(obj), true);
                                    }
                                });
                            }
                        } else {
                            console.log('------error recipient------');
                            console.log(error);
                            console.log('------end error recipient------');
                        }
                    });
                break;
            case 'file' :
                Recipient.findOneAndUpdate(
                    {live_chat_id: chatId},
                    {
                        last_message: new Date(),
                    },
                    {upsert: true, new: true, setDefaultsOnInsert: true},
                    function (error, res) {
                        if (!error) {
                            if (res.live_customer_id === event.author_id) {



                                if (event.thumbnail_url) {
                                    attachmentSave = {
                                        type: 'image',
                                        name: event.name,
                                        url: event.url,
                                        preview_url: event.thumbnail_url
                                    };

                                    attachmentSend = {
                                        image_data: {
                                            url: event.url,
                                            preview_url: event.thumbnail_url,
                                        }
                                    }
                                } else {
                                    attachmentSave = {
                                        type: 'file',
                                        name: event.name,
                                        url: event.url
                                    };

                                    attachmentSend = {
                                        file_url: event.url,
                                        name: event.name
                                    }
                                }
                                let msg = new Message({
                                    sender_id: res.recipient_id,
                                    recipient_id: res.recipient_id,
                                    type: 'attachment',
                                    message_id: event.id,
                                    attachments: [attachmentSave]
                                });

                                msg.save(function (err, data) {
                                    if (!err) {
                                        let obj = {
                                            from: {
                                                name: res.recipient_name,
                                                id: res.recipient_id,
                                            },
                                            attachments: {
                                                data: [attachmentSend]
                                            },
                                            id: event.id,
                                            created_time: data.created
                                        };
                                        io.emit('receivedMessage', res.recipient_id, JSON.stringify(obj), false);
                                    }
                                });
                            } else {
                                if (event.thumbnail_url) {
                                    attachmentSave = {
                                        type: 'image',
                                        name: event.name,
                                        url: event.url,
                                        preview_url: event.thumbnail_url
                                    };

                                    attachmentSend = {
                                        image_data: {
                                            url: event.url,
                                            preview_url: event.thumbnail_url,
                                        }
                                    }
                                } else {
                                    attachmentSave = {
                                        type: 'file',
                                        name: event.name,
                                        url: event.url
                                    };

                                    attachmentSend = {
                                        file_url: event.url,
                                        name: event.name
                                    }
                                }

                                let msg = new Message({
                                    sender_id: ADMIN_ID,
                                    recipient_id: res.recipient_id,
                                    type: 'attachment',
                                    message_id: event.id,
                                    attachments: [attachmentSave]
                                });

                                msg.save(function (err, data) {
                                    if (!err) {
                                        let obj = {
                                            from: {
                                                name: ADMIN_NAME,
                                                id: ADMIN_ID,
                                            },
                                            attachments: {
                                                data: [attachmentSend]
                                            },
                                            id: event.id,
                                            created_time: data.created
                                        };
                                        io.emit('receivedMessage', res.recipient_id, JSON.stringify(obj), true);
                                    }
                                });
                            }
                        }
                    });
                break;
        }
    });

    chatSDK.on('agent_disconnected', function () {
        refreshLiveChatToken().then((data) => {
            chatSDK.init({
                access_token: data.access_token
            });
        })
    });

    // for restart app
    refreshLiveChatToken().then((data) => {
        chatSDK.init({
            access_token: data.access_token
        });

    });
});

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function (req, res) {
    if (!res.signature_matched) {
        return res.sendStatus(403);
    }
    if (req.query['hub.mode'] === 'subscribe' &&
        req.query['hub.verify_token'] === VALIDATION_TOKEN) {
        console.log("Validating webhook");
        res.status(200).send(req.query['hub.challenge']);
    } else {
        console.error("Failed validation. Make sure the validation tokens match.");
        res.sendStatus(403);
    }
});

/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
    if (!res.signature_matched) {
        return res.sendStatus(403);
    }

    var data = req.body;
    // Make sure this is a page subscription
    if (data.object === 'page') {
        data.entry.forEach(function (pageEntry) {
            var pageId = pageEntry.id;
            var timeOfEvent = pageEntry.time;

            // Iterate over each messaging event
            pageEntry.messaging.forEach(function (messagingEvent) {
                if (messagingEvent.optin) {
                    receivedAuthentication(messagingEvent);
                } else if (messagingEvent.message) {
                    receivedMessage(messagingEvent);
                } else if (messagingEvent.read) {
                    console.log('Received Read event');
                } else if (messagingEvent.delivery) {
                    console.log('Received Delivery event');
                } else {
                    console.log("Webhook received unknown messagingEvent: ", messagingEvent);
                }
            });
        });
        res.sendStatus(200);
    }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function (req, res) {
    var accountLinkingToken = req.query.account_linking_token;
    var redirectURI = req.query.redirect_uri;

    // Authorization Code should be generated per user by the developer. This will
    // be passed to the Account Linking callback.
    var authCode = "1234567890";

    // Redirect users to this URI on successful login
    var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

    res.render('authorize', {
        accountLinkingToken: accountLinkingToken,
        redirectURI: redirectURI,
        redirectURISuccess: redirectURISuccess
    });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
    //verify Facebook
    if (req.headers["x-hub-signature"]) {
        let signature = req.headers["x-hub-signature"];
        var elements = signature.split('=');
        var method = elements[0];
        var signatureHash = elements[1];

        var expectedHash = crypto.createHmac('sha1', APP_SECRET).update(buf).digest('hex');
        if (signatureHash === expectedHash) {
            res.signature_matched = true;
        }
    }
    //verify Line
    else if (req.headers["x-line-signature"]) {
        let signature = req.headers["x-line-signature"];
        let expectedHash = crypto.createHmac('SHA256', LINE_CHANNEL_SECRET).update(buf).digest('base64');
        if (signature === expectedHash) {
            res.signature_matched = true;
        }
    }
    //verify CRM
    else if (req.headers["x-crm-signature"]) {
        let signature = req.headers["x-crm-signature"];
        let expectedHash = crypto.createHmac('SHA256', VALIDATION_KEY).update(buf).digest('base64');

        if (signature === expectedHash) {
            res.signature_matched = true;
        }
    }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
    var senderId = event.sender.id;
    var recipientId = event.recipient.id;
    var timeOfAuth = event.timestamp;

    // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
    // The developer can set this to an arbitrary value to associate the
    // authentication callback with the 'Send to Messenger' click event. This is
    // a way to do account linking when the user clicks the 'Send to Messenger'
    // plugin.
    var passThroughParam = event.optin.ref;

    console.log("Received authentication for user %d and page %d with pass " +
        "through param '%s' at %d", senderId, recipientId, passThroughParam,
        timeOfAuth);

    // When an authentication is received, we'll send a message back to the sender
    // to let them know it was successful.
    sendTextMessage(senderId, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 */
function receivedMessage(event) {
    var senderId = event.sender.id;
    var recipientId = event.recipient.id;
    var timeOfMessage = event.timestamp;
    var message = event.message;

    console.log("Received message from user %d to page %d at %d with message:",
        senderId, recipientId, timeOfMessage);
    retrieveMessageInfo(message.mid, senderId, false);
}

function retrieveMessageInfo(id, recipientId, owner) {
    request({
        uri: 'https://graph.facebook.com/v5.0/' + recipientId + '?fields=name',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'GET'
    }, function (err, res, body) {
        if (!err && res.statusCode === 200) {
            let result = JSON.parse(body);
            Recipient.findOneAndUpdate(
                {recipient_id: recipientId},
                {
                    recipient_name: result.name,
                    type: 'Facebook',
                    last_message: new Date(),
                },
                {upsert: true, new: true, setDefaultsOnInsert: true},
                function (error) {
                    if (!error) {
                        request({
                            uri: 'https://graph.facebook.com/v5.0/' + id + '?fields=from,message,attachments,sticker,created_time',
                            qs: {access_token: PAGE_ACCESS_TOKEN},
                            method: 'GET'
                        }, function (error, response, body) {
                            if (!error && response.statusCode === 200) {
                                let data = JSON.parse(body);
                                let msg;
                                if (data.sticker) {
                                    msg = new Message({
                                        sender_id: owner ? ADMIN_ID : recipientId,
                                        recipient_id: recipientId,
                                        type: 'sticker',
                                        message_id: data.id,
                                        message_text: data.sticker,
                                        created: data.created_time,
                                    });
                                } else if (data.attachments) {
                                    let attachments = [];
                                    data.attachments.data.forEach(function (i) {
                                        if (i.image_data) {
                                            attachments.push({
                                                type: 'image',
                                                url: i.image_data.url,
                                                preview_url: i.image_data.preview_url
                                            });
                                        } else {
                                            attachments.push({type: 'file', url: i.file_url, name: i.name});
                                        }
                                    });
                                    msg = new Message({
                                        sender_id: owner ? ADMIN_ID : recipientId,
                                        recipient_id: recipientId,
                                        type: 'attachment',
                                        message_id: data.id,
                                        attachments: attachments,
                                        created: data.created_time,
                                    });
                                } else {
                                    msg = new Message({
                                        sender_id: owner ? ADMIN_ID : recipientId,
                                        recipient_id: recipientId,
                                        type: 'text',
                                        message_id: data.id,
                                        message_text: data.message,
                                        created: data.created_time,
                                    });
                                }
                                //Save Facebook Message
                                msg.save(function (err, data) {
                                    if (!err) {
                                        io.emit('receivedMessage', recipientId, body, owner);
                                    }
                                });
                            } else {
                                console.error("Failed retrieving Message info", response.statusCode, response.statusMessage, body.error);
                            }
                        });
                    }
                });
        } else {
            console.log('Fail to retrieve user info', res.statusCode, res.statusMessage, body.error)
        }
    });
}

function sendMarkSeen(recipientId) {
    console.log("Mark last message as seen", recipientId);
    var messageData = {
        messaging_type: "MESSAGE_TAG",
        tag: "ISSUE_RESOLUTION",
        recipient: {
            id: recipientId
        },
        sender_action: "mark_seen"
    };

    callSendAPI(messageData);
}

function sendAttachment(recipientId, url, type) {
    if (typeof type === 'undefined') {
        type = 'file';
    }
    var messageData = {
        messaging_type: "MESSAGE_TAG",
        tag: "ISSUE_RESOLUTION",
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: type,
                payload: {
                    url: url
                }
            }
        }
    };

    callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
    var messageData = {
        messaging_type: "MESSAGE_TAG",
        tag: "ISSUE_RESOLUTION",
        recipient: {
            id: recipientId
        },
        message: {
            text: messageText
        }
    };

    callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
    request({
        uri: 'https://graph.facebook.com/v5.0/me/messages',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'POST',
        json: messageData

    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            var recipientId = body.recipient_id;
            var messageId = body.message_id;
            if (messageId) {
                console.log("Successfully sent message with id %s to recipient %s", messageId, recipientId);
                retrieveMessageInfo(messageId, recipientId, true);
            } else {
                console.log("Successfully called Send API for recipient %s", recipientId);
            }
        } else {
            console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
        }
    });
}

/* ****************LINE EVENT******************* */
function receivedLineMessage(event) {
    request({
        url: 'https://api.line.me/v2/bot/profile/' + event.source.userId,
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + LINE_ACCESS_TOKEN
        },
        encoding: null
    }, function (err, res, body) {
        let profile = JSON.parse(body);
        Recipient.findOneAndUpdate(
            {recipient_id: event.source.userId},
            {
                recipient_name: profile.displayName,
                type: 'Line',
                last_message: new Date(),
            },
            {upsert: true, new: true, setDefaultsOnInsert: true},
            function (error) {
                if (!error) {
                    switch (event.message.type) {
                        case 'text':
                            let msg = new Message({
                                sender_id: event.source.userId,
                                recipient_id: event.source.userId,
                                type: 'text',
                                message_id: event.message.id,
                                message_text: event.message.text
                            });
                            msg.save(function (err, data) {
                                if (!err) {
                                    let obj = {
                                        from: {
                                            name: profile.displayName,
                                            id: profile.userId,
                                        },
                                        message: event.message.text,
                                        id: event.message.id,
                                        created_time: data.created
                                    };
                                    io.emit('receivedMessage', event.source.userId, JSON.stringify(obj), false);
                                }
                            });
                            break;
                        case 'image':
                            request({
                                url: 'https://api-data.line.me/v2/bot/message/' + event.message.id + '/content',
                                method: 'GET',
                                headers: {
                                    'Authorization': 'Bearer ' + LINE_ACCESS_TOKEN
                                },
                                encoding: null
                            }, function (error, response, body) {
                                if (!error && response.statusCode === 200) {
                                    let dir = './public/uploads';
                                    if (!fs.existsSync(dir)) {
                                        fs.mkdirSync(dir);
                                    }
                                    fs.writeFileSync(dir + '/' + event.message.id + '.png', Buffer.from(body));

                                    let msg = new Message({
                                        sender_id: event.source.userId,
                                        recipient_id: event.source.userId,
                                        type: 'attachment',
                                        message_id: event.message.id,
                                        attachments: [
                                            {
                                                type: 'image',
                                                url: SERVER_URL + '/uploads/' + event.message.id + '.png',
                                                preview_url: SERVER_URL + '/uploads/' + event.message.id + '.png',
                                            }
                                        ]
                                    });

                                    msg.save(function (err, data) {
                                        if (!err) {
                                            let obj = {
                                                from: {
                                                    name: profile.displayName,
                                                    id: profile.userId,
                                                },
                                                attachments: {
                                                    data: [
                                                        {
                                                            image_data: {
                                                                url: SERVER_URL + '/uploads/' + event.message.id + '.png',
                                                                preview_url: SERVER_URL + '/uploads/' + event.message.id + '.png',
                                                            }
                                                        }
                                                    ]
                                                },
                                                id: event.message.id,
                                                created_time: data.created
                                            };
                                            io.emit('receivedMessage', event.source.userId, JSON.stringify(obj), false);
                                        }
                                    });
                                }
                            });
                            break;
                        default:
                            console.log('----Received a Line message: This file type ' + event.message.type + ' does not support yet.')
                    }
                } else {
                    console.log('------error recipient------');
                    console.log(error);
                    console.log('------end error recipient------');
                }
            });
    });
}

function sendLineTextMessage(recipientId, messageText) {
    request({
        url: 'https://api.line.me/v2/bot/message/push',
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + LINE_ACCESS_TOKEN,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            to: recipientId,
            messages: [{type: "text", text: messageText}]
        })
    }, function (err, res, body) {
        let msg = new Message({
            sender_id: ADMIN_ID,
            recipient_id: recipientId,
            type: 'text',
            message_text: messageText
        });
        msg.save(function (err, data) {
            if (!err) {
                let obj = {
                    from: {
                        name: ADMIN_NAME,
                        id: ADMIN_ID,
                    },
                    message: data.message_text,
                    id: data.message_id,
                    created_time: data.created
                };
                io.emit('receivedMessage', recipientId, JSON.stringify(obj), true);
            }
        });
    });
}

function sendLineImage(recipientId, url, previewUrl) {
    request({
        url: 'https://api.line.me/v2/bot/message/push',
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + LINE_ACCESS_TOKEN,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            to: recipientId,
            messages: [{type: "image", originalContentUrl: url, previewImageUrl: previewUrl}]
        })
    }, function (err, res, body) {
        let msg = new Message({
            sender_id: ADMIN_ID,
            recipient_id: recipientId,
            type: 'attachment',
            attachments: [
                {
                    type: 'image',
                    url: url,
                    preview_url: previewUrl,
                }
            ]
        });

        msg.save(function (err, data) {
            if (!err) {
                let obj = {
                    from: {
                        name: ADMIN_NAME,
                        id: ADMIN_ID,
                    },
                    attachments: {
                        data: [
                            {
                                image_data: {
                                    url: url,
                                    preview_url: previewUrl,
                                }
                            }
                        ]
                    },
                    id: data.message_id,
                    created_time: data.created
                };
                io.emit('receivedMessage', recipientId, JSON.stringify(obj), true);
            }
        });
    });
}

/* ***************END LINE EVENT**************** */


/* ***************LIVE CHAT********************* */
function registerLiveChatWebHook(configData) {
    //incoming_chat_thread
    request({
        url: 'https://api.livechatinc.com/v3.1/configuration/action/register_webhook',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': configData.token_type + ' ' + configData.access_token
        },
        body: JSON.stringify({
            url: SERVER_URL + '/live-chat-start',
            description: 'Thread Start',
            action: 'incoming_chat_thread',
            secret_key: VALIDATION_KEY
        })
    }, function (err, res, body) {
        if (!err && res.statusCode === 200) {
            console.log('Register incoming_chat_thread successful !');
            console.log(body);
            fs.writeFileSync('incoming_chat_thread.json', body);
        } else {
            console.log('Register incoming_chat_thread error !')
        }
    });
    //incoming_event
    request({
        url: 'https://api.livechatinc.com/v3.1/configuration/action/register_webhook',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': configData.token_type + ' ' + configData.access_token
        },
        body: JSON.stringify({
            url: SERVER_URL + '/live-chat-incoming-event',
            description: 'Incomming event',
            action: 'incoming_event',
            secret_key: VALIDATION_KEY
        })
    }, function (err, res, body) {
        if (!err && res.statusCode === 200) {
            console.log('Register incoming_event successful !');
            console.log(body);
            fs.writeFileSync('incoming_event.json', body);
        } else {
            console.log('Register incoming_event error !')
        }
    });
    //thread_closed
    request({
        url: 'https://api.livechatinc.com/v3.1/configuration/action/register_webhook',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': configData.token_type + ' ' + configData.access_token
        },
        body: JSON.stringify({
            url: SERVER_URL + '/live-chat-close',
            description: 'Thread End',
            action: 'thread_closed',
            secret_key: VALIDATION_KEY
        })
    }, function (err, res, body) {
        if (!err && res.statusCode === 200) {
            console.log('Register thread_closed successful !');
            console.log(body);
            fs.writeFileSync('thread_closed.json', body);
        } else {
            console.log('Register thread_closed error !')
        }
    });
    //Create chat bot
    request({
        url: 'https://api.livechatinc.com/v3.1/configuration/action/create_bot_agent',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': configData.token_type + ' ' + configData.access_token
        },
        body: JSON.stringify({
            name: 'Support',
            status: 'accepting chats'
        })
    }, function (err, res, body) {
        if (!err && res.statusCode === 200) {
            console.log('A chat bot has bean created !');
            console.log(body);
        }
    });
}

function markSeenLiveChat(chatId, time) {
    let configData = JSON.parse(fs.readFileSync(LIVECHAT_CONFIG_FILE));
    request({
        url: 'https://api.livechatinc.com/v3.1/agent/action/mark_events_as_seen',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': configData.token_type + ' ' + configData.access_token
        },
        body: JSON.stringify({
            chat_id: chatId,
            seen_up_to: time
        })
    }, function (err, res, body) {
        if (!err && res.statusCode === 200) {
            console.log('--- mark seen ----', new Date());
        } else {
            console.log(err)
            console.log(chatId + ' ---- ' + time);
        }
    });
}

async function refreshLiveChatToken() {
    return new Promise((resolve) => {
        try {
            let config = fs.readFileSync(LIVECHAT_CONFIG_FILE);
            let configData = JSON.parse(config);

            request({
                url: 'https://accounts.livechatinc.com/token',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    grant_type: "refresh_token",
                    refresh_token: configData.refresh_token,
                    client_id: LIVECHAT_CLIENT_ID,
                    client_secret: LIVECHAT_CLIENT_SECRET
                })
            }, function (error, response, body) {
                if (!error && response.statusCode === 200) {
                    fs.writeFileSync(LIVECHAT_CONFIG_FILE, body);
                    let data = JSON.parse(body);
                    console.log('-----Refresh Token at ' + new Date() + ' ---------');
                    return resolve(data);
                }
            });
        } catch (e) {
            console.log('Live Chat is not authorized');
        }
    })
}

async function sendLiveChatTextMessage(recipientId, messageText) {
    const recipient = await Recipient.findOne({recipient_id: recipientId});
    if (recipient) {
        chatSDK.sendMessage(recipient.live_chat_id, messageText).then(function() {
            //do nothing
        });
    }
}

async function sendLiveChatFileMessage(recipientId, url) {
    const recipient = await Recipient.findOne({recipient_id: recipientId});
    await chatSDK.methodFactory({
        action: 'send_event',
        payload: {
            chat_id: recipient.live_chat_id,
            event: {
                type: 'file',
                url: url,
                recipients: 'all'
            }
        }
    });
}

/* *************END LIVE CHAT******************* */
module.exports = app;
