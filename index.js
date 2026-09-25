```js
const express = require('express');
const crypto = require('crypto');

const app = express();

// ============================================================
// CONFIGURATION
// ============================================================

const SHOP = process.env.SHOP || 'wellessia';

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

const SHOPIFY_WEBHOOK_SECRET =
  process.env.SHOPIFY_WEBHOOK_SECRET || CLIENT_SECRET;

const SHOPIFY_API_VERSION =
  process.env.SHOPIFY_API_VERSION || '2026-07';

// SSL Wireless SMS Plus (Dynamic SMS) API
const SSL_API_URL =
  process.env.SSL_API_URL ||
  'https://smsplus.sslwireless.com/api/v3/send-sms/dynamic';

const SSL_API_TOKEN = process.env.SSL_API_TOKEN;
const SSL_SID = process.env.SSL_SID;

// Message template.
// Placeholders:
// {{name}} {{order_number}} {{items}} {{total}} {{currency}}
const MSG_ORDER_CREATED =
  process.env.MSG_ORDER_CREATED ||
  'Hi {{name}}, your order #{{order_number}} ({{items}}) worth {{currency}} {{total}} has been placed successfully. Thank you for shopping with us!';

const PORT = process.env.PORT || 3000;

// ============================================================
// ENVIRONMENT VALIDATION
// ============================================================

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('❌ Missing CLIENT_ID or CLIENT_SECRET');
  process.exit(1);
}

if (!SSL_API_TOKEN || !SSL_SID) {
  console.error('❌ Missing SSL_API_TOKEN or SSL_SID');
  process.exit(1);
}

if (!SHOPIFY_WEBHOOK_SECRET) {
  console.error('❌ Missing SHOPIFY_WEBHOOK_SECRET');
  process.exit(1);
}

// ============================================================
// DEPLOYMENT CUTOFF
// ============================================================
//
// Any Shopify order whose created_at is BEFORE this timestamp
// will be ignored by the webhook handler.
//
// This prevents old / backlog / redelivered webhooks from
// sending SMS after Railway restarts or redeploys.
//
// ============================================================

const SERVER_STARTED_AT = new Date();

console.log(
  `🕒 Server started at: ${SERVER_STARTED_AT.toISOString()}`
);

console.log(
  '   Orders created before this time will be skipped by the webhook.'
);

// ============================================================
// TOKEN CACHE (Shopify)
// ============================================================

let SHOPIFY_TOKEN = null;
let SHOPIFY_EXPIRES_AT = 0;

// ============================================================
// DUPLICATE PROTECTION
// ============================================================

const submittedOrders = new Map();

// ============================================================
// EXPRESS JSON BODY
// ============================================================

app.use(
  express.json({
    limit: '1mb',
    verify: (req, res, buf) => {
      req.rawBody = Buffer.from(buf);
    }
  })
);

// ============================================================
// SHOPIFY WEBHOOK HMAC VERIFICATION
// ============================================================

function verifyShopifyWebhook(req) {
  try {
    const hmacHeader = req.get(
      'X-Shopify-Hmac-Sha256'
    );

    if (!hmacHeader) {
      console.error(
        '❌ Missing X-Shopify-Hmac-Sha256 header'
      );
      return false;
    }

    if (!req.rawBody) {
      console.error(
        '❌ Raw webhook body is missing'
      );
      return false;
    }

    const generatedHash = crypto
      .createHmac(
        'sha256',
        SHOPIFY_WEBHOOK_SECRET
      )
      .update(req.rawBody)
      .digest('base64');

    const receivedBuffer = Buffer.from(
      hmacHeader,
      'utf8'
    );

    const generatedBuffer = Buffer.from(
      generatedHash,
      'utf8'
    );

    if (
      receivedBuffer.length !==
      generatedBuffer.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      receivedBuffer,
      generatedBuffer
    );
  } catch (error) {
    console.error(
      'Webhook HMAC verification error:',
      error.message
    );

    return false;
  }
}

// ============================================================
// SHOPIFY ACCESS TOKEN
// ============================================================

async function getShopifyToken() {
  if (
    SHOPIFY_TOKEN &&
    Date.now() <
      SHOPIFY_EXPIRES_AT - 60000
  ) {
    return SHOPIFY_TOKEN;
  }

  console.log(
    '🔐 Requesting Shopify access token...'
  );

  const tokenUrl =
    `https://${SHOP}.myshopify.com/admin/oauth/access_token`;

  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET
  });

  const response = await fetch(
    tokenUrl,
    {
      method: 'POST',
      headers: {
        'Content-Type':
          'application/x-www-form-urlencoded'
      },
      body: body.toString()
    }
  );

  const data = await response.json();

  if (!response.ok) {
    console.error(
      '❌ Shopify token response:',
      JSON.stringify(
        data,
        null,
        2
      )
    );

    throw new Error(
      `Shopify token error ${response.status}: ${
        data.error_description ||
        data.error ||
        JSON.stringify(data)
      }`
    );
  }

  if (!data.access_token) {
    throw new Error(
      'Shopify response did not contain access_token'
    );
  }

  SHOPIFY_TOKEN =
    data.access_token;

  SHOPIFY_EXPIRES_AT =
    Date.now() +
    (data.expires_in || 86400) *
      1000;

  console.log(
    '✅ Shopify access token obtained'
  );

  return SHOPIFY_TOKEN;
}

// ============================================================
// SHOPIFY API REQUEST
// ============================================================

async function shopifyRequest(
  endpoint,
  options = {}
) {
  const token =
    await getShopifyToken();

  const url =
    `https://${SHOP}.myshopify.com/admin/api/` +
    `${SHOPIFY_API_VERSION}/${endpoint}`;

  const response = await fetch(
    url,
    {
      method:
        options.method || 'GET',

      headers: {
        'X-Shopify-Access-Token':
          token,

        'Content-Type':
          'application/json',

        ...(options.headers || {})
      },

      body: options.body
        ? JSON.stringify(options.body)
        : undefined
    }
  );

  const text =
    await response.text();

  let data;

  try {
    data = text
      ? JSON.parse(text)
      : {};
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    const error =
      new Error(
        `Shopify API ${response.status}`
      );

    error.status =
      response.status;

    error.data = data;

    throw error;
  }

  return data;
}

// ============================================================
// SSL WIRELESS SMS REQUEST
// ============================================================

async function sendSms(
  phone,
  message,
  csmsId
) {
  const body = {
    api_token:
      SSL_API_TOKEN,

    sid:
      SSL_SID,

    sms: [
      {
        msisdn:
          phone,

        text:
          message,

        csms_id:
          csmsId
      }
    ]
  };

  const response =
    await fetch(
      SSL_API_URL,
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/json'
        },

        body:
          JSON.stringify(body)
      }
    );

  const data =
    await response.json();

  if (
    data.status !==
    'SUCCESS'
  ) {
    const detail =
      (
        data.smsinfo &&
        data.smsinfo[0] &&
        data.smsinfo[0]
          .status_message
      ) ||
      data.error_message;

    const error =
      new Error(
        `SSL Wireless rejected the SMS: ${
          detail || data.status
        }`
      );

    error.data =
      data;

    throw error;
  }

  return data;
}

// ============================================================
// NORMALIZE BANGLADESH PHONE
// ============================================================
//
// Examples:
// +8801741563884  → 8801741563884
// 8801741563884   → 8801741563884
// 01741563884     → 8801741563884
//
// ============================================================

function normalizePhone(
  phone
) {
  if (!phone) {
    return '';
  }

  let value =
    String(phone).trim();

  // Remove spaces, hyphens, brackets, plus signs
  value =
    value.replace(
      /[\s\-()+]/g,
      ''
    );

  if (
    value.startsWith('880')
  ) {
    // Already has country code
  } else if (
    value.startsWith('0')
  ) {
    value =
      '880' +
      value.substring(1);
  } else if (
    value.length === 10
  ) {
    value =
      '880' + value;
  }

  // Bangladesh mobile number:
  // 13 digits including country code
  if (
    !/^\d{13}$/.test(value)
  ) {
    return '';
  }

  return value;
}

// ============================================================
// BUILD SMS MESSAGE FROM SHOPIFY ORDER
// ============================================================

function buildOrderSms(
  shopifyOrder
) {
  const shipping =
    shopifyOrder.shipping_address ||
    {};

  const billing =
    shopifyOrder.billing_address ||
    {};

  const items =
    shopifyOrder.line_items ||
    [];

  // ---- Recipient name ----

  const recipientName =
    shipping.name ||
    billing.name ||
    shopifyOrder.customer?.first_name ||
    'Customer';

  // ---- Recipient phone ----

  const recipientPhone =
    shipping.phone ||
    billing.phone ||
    shopifyOrder.customer?.phone ||
    shopifyOrder.phone ||
    '';

  const cleanedPhone =
    normalizePhone(
      recipientPhone
    );

  // ---- Products purchased ----

  const itemsDescription =
    items
      .map((item) => {
        const title =
          item.title ||
          item.name ||
          'Product';

        const quantity =
          Number(
            item.quantity
          ) || 1;

        return `${title} x${quantity}`;
      })
      .join(', ');

  // ---- Order total ----

  const totalPrice =
    shopifyOrder.total_price ||
    '0.00';

  const currency =
    shopifyOrder.currency ||
    '';

  // ---- Fill message template ----

  const message =
    MSG_ORDER_CREATED
      .replace(
        '{{name}}',
        recipientName
      )
      .replace(
        '{{order_number}}',
        shopifyOrder.order_number ||
          shopifyOrder.name ||
          shopifyOrder.id
      )
      .replace(
        '{{items}}',
        itemsDescription ||
          'your items'
      )
      .replace(
        '{{total}}',
        totalPrice
      )
      .replace(
        '{{currency}}',
        currency
      );

  return {
    phone:
      cleanedPhone,

    message,

    recipientName,

    itemsDescription
  };
}

// ============================================================
// HEALTH CHECK
// ============================================================

app.get(
  '/',
  (req, res) => {
    res.json({
      success: true,
      status: 'ok',
      service:
        'Shopify SMS Bridge',
      shop: SHOP,
      shopify_api_version:
        SHOPIFY_API_VERSION,
      webhook:
        '/webhooks/orders-create',
      server_started_at:
        SERVER_STARTED_AT.toISOString()
    });
  }
);

app.get(
  '/health',
  (req, res) => {
    res.json({
      success: true,
      status: 'healthy',
      timestamp:
        new Date().toISOString(),
      server_started_at:
        SERVER_STARTED_AT.toISOString()
    });
  }
);

// ============================================================
// SHOW THIS SERVER'S OUTBOUND IP
// ============================================================

app.get(
  '/api/my-ip',
  async (req, res) => {
    try {
      const response =
        await fetch(
          'https://api.ipify.org?format=json'
        );

      const data =
        await response.json();

      res.json({
        success: true,
        outbound_ip:
          data.ip
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SHOPIFY ORDERS CREATE WEBHOOK
// ============================================================

app.post(
  '/webhooks/orders-create',
  async (req, res) => {
    console.log(
      '\n============================================'
    );

    console.log(
      '📩 SHOPIFY ORDERS/CREATE WEBHOOK RECEIVED'
    );

    console.log(
      '============================================'
    );

    // --------------------------------------------------------
    // Verify Shopify HMAC
    // --------------------------------------------------------

    const valid =
      verifyShopifyWebhook(req);

    if (!valid) {
      console.error(
        '❌ Invalid Shopify webhook signature'
      );

      return res.status(401).json({
        success: false,
        error:
          'Invalid Shopify webhook signature'
      });
    }

    console.log(
      '✅ Shopify webhook signature verified'
    );

    const shopifyOrder =
      req.body;

    if (
      !shopifyOrder ||
      !shopifyOrder.id
    ) {
      console.error(
        '❌ Invalid Shopify order webhook'
      );

      return res.status(400).json({
        success: false,
        error:
          'Invalid Shopify order webhook payload'
      });
    }

    const shopifyOrderId =
      String(
        shopifyOrder.id
      );

    console.log(
      '🛒 Shopify Order ID:',
      shopifyOrderId
    );

    console.log(
      '🧾 Shopify Order Name:',
      shopifyOrder.name ||
        'N/A'
    );

    // ========================================================
    // DEPLOYMENT CUTOFF CHECK
    // ========================================================

    const orderCreatedAt =
      shopifyOrder.created_at
        ? new Date(
            shopifyOrder.created_at
          )
        : null;

    if (
      !orderCreatedAt ||
      Number.isNaN(
        orderCreatedAt.getTime()
      )
    ) {
      console.log(
        '⏭️ Skipping SMS — order created_at is missing or invalid'
      );

      return res.status(200).json({
        success: true,
        skipped: true,
        reason:
          'Missing or invalid order created_at',
        shopify_order_id:
          shopifyOrderId
      });
    }

    console.log(
      '🕒 Order Created At:',
      orderCreatedAt.toISOString()
    );

    console.log(
      '🕒 Server Started At:',
      SERVER_STARTED_AT.toISOString()
    );

    if (
      orderCreatedAt <
      SERVER_STARTED_AT
    ) {
      console.log(
        '⏭️ Skipping SMS — order was created before server startup'
      );

      return res.status(200).json({
        success: true,
        skipped: true,
        reason:
          'Order created before server startup',

        shopify_order_id:
          shopifyOrderId,

        order_created_at:
          orderCreatedAt.toISOString(),

        server_started_at:
          SERVER_STARTED_AT.toISOString()
      });
    }

    console.log(
      '✅ Order passed deployment cutoff'
    );

    // ========================================================
    // ONLINE STORE / WEB ORDER CHECK
    // ========================================================
    //
    // Only orders with source_name === "web"
    // will receive automatic SMS.
    //
    // Manual/Admin/Draft/other source orders
    // will be skipped.
    //
    // ========================================================

    const orderSource =
      shopifyOrder.source_name ||
      '';

    console.log(
      '🔗 Order Source:',
      orderSource ||
        'N/A'
    );

    if (
      orderSource !==
      'web'
    ) {
      console.log(
        `⏭️ Skipping SMS — order source is "${orderSource}", not an online store order`
      );

      return res.status(200).json({
        success: true,
        skipped: true,
        reason:
          `order source is "${orderSource}", not web`,

        source_name:
          orderSource ||
          null,

        shopify_order_id:
          shopifyOrderId
      });
    }

    console.log(
      '✅ Online Store/Web order confirmed'
    );

    console.log(
      '📨 Automatic SMS is allowed for this order'
    );

    // ========================================================
    // DUPLICATE PROTECTION
    // ========================================================

    if (
      submittedOrders.has(
        shopifyOrderId
      )
    ) {
      console.log(
        '⚠️ SMS already sent for this order'
      );

      return res.status(200).json({
        success: true,
        duplicate: true,
        message:
          'SMS was already sent for this order',
        previous_result:
          submittedOrders.get(
            shopifyOrderId
          )
      });
    }

    // ========================================================
    // BUILD SMS FROM ORDER
    // ========================================================

    const {
      phone,
      message,
      recipientName,
      itemsDescription
    } =
      buildOrderSms(
        shopifyOrder
      );

    console.log(
      '👤 Recipient:',
      recipientName
    );

    console.log(
      '📱 Phone:',
      phone ||
        'MISSING/INVALID'
    );

    console.log(
      '🛍️ Items:',
      itemsDescription ||
        'N/A'
    );

    console.log(
      '💬 Message:',
      message
    );

    // ========================================================
    // ACKNOWLEDGE SHOPIFY QUICKLY
    // ========================================================
    //
    // Respond to Shopify before sending SMS so the webhook
    // doesn't time out and get retried.
    //
    // ========================================================

    res.status(200).json({
      success: true,
      shopify_order_id:
        shopifyOrderId,
      source_name:
        orderSource
    });

    // ========================================================
    // PHONE CHECK
    // ========================================================

    if (!phone) {
      console.warn(
        `⚠️ No valid phone number for order ${shopifyOrderId}, skipping SMS`
      );

      return;
    }

    // ========================================================
    // SEND SMS
    // ========================================================

    const csmsId =
      `${shopifyOrderId}-${Date.now()}`
        .slice(0, 20);

    try {
      console.log(
        '\n📨 Sending SMS via SSL Wireless...'
      );

      const result =
        await sendSms(
          phone,
          message,
          csmsId
        );

      const smsResult = {
        success: true,

        shopify_order_id:
          shopifyOrder.id,

        shopify_order_name:
          shopifyOrder.name,

        source_name:
          orderSource,

        phone,

        sms_response:
          result
      };

      submittedOrders.set(
        shopifyOrderId,
        smsResult
      );

      console.log(
        '\n============================================'
      );

      console.log(
        '✅ SHOPIFY WEB ORDER → SMS SUCCESS'
      );

      console.log(
        '============================================'
      );

      console.log(
        JSON.stringify(
          smsResult,
          null,
          2
        )
      );
    } catch (error) {
      console.error(
        '\n❌ SMS SEND FAILED'
      );

      console.error(
        error.data ||
          error.message
      );

      submittedOrders.set(
        shopifyOrderId,
        {
          success: false,

          shopify_order_id:
            shopifyOrderId,

          error:
            error.message
        }
      );
    }
  }
);

// ============================================================
// TEST SHOPIFY CONNECTION
// ============================================================

app.get(
  '/api/test/shopify',
  async (req, res) => {
    try {
      const data =
        await shopifyRequest(
          'shop.json'
        );

      res.json({
        success: true,
        message:
          'Shopify API connection working',
        shop:
          data.shop
      });
    } catch (error) {
      console.error(
        'Shopify test error:',
        error.data ||
          error.message
      );

      res.status(
        error.status ||
          500
      ).json({
        success: false,
        service:
          'shopify',
        error:
          error.message,
        details:
          error.data ||
          null
      });
    }
  }
);

// ============================================================
// TEST SSL WIRELESS SMS
// ============================================================

app.get(
  '/api/test/sms',
  async (req, res) => {
    try {
      const phone =
        normalizePhone(
          req.query.phone
        );

      if (!phone) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              'Pass a valid BD phone number as ?phone=01XXXXXXXXX'
          });
      }

      const result =
        await sendSms(
          phone,

          'This is a test message from your Shopify SMS bridge.',

          `test-${Date.now()}`
        );

      res.json({
        success: true,
        message:
          'Test SMS sent',
        sms_response:
          result
      });
    } catch (error) {
      console.error(
        'SMS test error:',
        error.data ||
          error.message
      );

      res.status(500).json({
        success: false,
        service:
          'sms',
        error:
          error.message,
        details:
          error.data ||
          null
      });
    }
  }
);

// ============================================================
// GET SHOPIFY ORDERS
// ============================================================

app.get(
  '/api/shopify/orders',
  async (req, res) => {
    try {
      const limit =
        Math.min(
          Math.max(
            parseInt(
              req.query.limit,
              10
            ) || 10,
            1
          ),
          250
        );

      const status =
        req.query.status ||
        'any';

      const data =
        await shopifyRequest(
          `orders.json?status=${encodeURIComponent(
            status
          )}&limit=${limit}`
        );

      res.json({
        success: true,
        count:
          data.orders?.length ||
          0,
        orders:
          data.orders ||
          []
      });
    } catch (error) {
      console.error(
        'Orders error:',
        error.data ||
          error.message
      );

      res.status(
        error.status ||
          500
      ).json({
        success: false,
        error:
          error.message,
        details:
          error.data ||
          null
      });
    }
  }
);

// ============================================================
// GET SINGLE SHOPIFY ORDER
// ============================================================

app.get(
  '/api/shopify/orders/:id',
  async (req, res) => {
    try {
      const orderId =
        encodeURIComponent(
          req.params.id
        );

      const data =
        await shopifyRequest(
          `orders/${orderId}.json`
        );

      res.json({
        success: true,
        order:
          data.order ||
          null
      });
    } catch (error) {
      console.error(
        'Single order error:',
        error.data ||
          error.message
      );

      res.status(
        error.status ||
          500
      ).json({
        success: false,
        error:
          error.message,
        details:
          error.data ||
          null
      });
    }
  }
);

// ============================================================
// PREVIEW SMS FOR A GIVEN ORDER
// ============================================================

app.get(
  '/api/shopify/order/:id/sms',
  async (req, res) => {
    try {
      const orderId =
        encodeURIComponent(
          req.params.id
        );

      const data =
        await shopifyRequest(
          `orders/${orderId}.json`
        );

      if (!data.order) {
        return res
          .status(404)
          .json({
            success: false,
            error:
              'Shopify order not found'
          });
      }

      const preview =
        buildOrderSms(
          data.order
        );

      res.json({
        success: true,

        shopify_order_id:
          data.order.id,

        source_name:
          data.order
            .source_name ||
          null,

        sms_preview:
          preview
      });
    } catch (error) {
      console.error(
        'SMS preview error:',
        error.data ||
          error.message
      );

      res.status(
        error.status ||
          500
      ).json({
        success: false,
        error:
          error.message,
        details:
          error.data ||
          null
      });
    }
  }
);

// ============================================================
// MANUALLY (RE)SEND SMS FOR A GIVEN SHOPIFY ORDER
// ============================================================
//
// This endpoint intentionally remains independent from the
// automatic webhook filter.
//
// If you manually call this endpoint, it will send the SMS
// regardless of the order source.
//
// ============================================================

app.post(
  '/api/sms/send/:shopifyOrderId',
  async (req, res) => {
    const shopifyOrderId =
      req.params.shopifyOrderId;

    try {
      const data =
        await shopifyRequest(
          `orders/${encodeURIComponent(
            shopifyOrderId
          )}.json`
        );

      const shopifyOrder =
        data.order;

      if (!shopifyOrder) {
        return res
          .status(404)
          .json({
            success: false,
            error:
              'Shopify order not found'
          });
      }

      const {
        phone,
        message
      } =
        buildOrderSms(
          shopifyOrder
        );

      if (!phone) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              'No valid phone number on this order'
          });
      }

      const csmsId =
        `${shopifyOrderId}-${Date.now()}`
          .slice(0, 20);

      const result =
        await sendSms(
          phone,
          message,
          csmsId
        );

      const smsResult = {
        success: true,

        shopify_order_id:
          shopifyOrder.id,

        shopify_order_name:
          shopifyOrder.name,

        source_name:
          shopifyOrder.source_name ||
          null,

        phone,

        sms_response:
          result
      };

      submittedOrders.set(
        String(
          shopifyOrderId
        ),
        smsResult
      );

      res.json(
        smsResult
      );
    } catch (error) {
      console.error(
        '❌ Manual SMS send error:',
        error.data ||
          error.message
      );

      res.status(
        error.status ||
          500
      ).json({
        success: false,

        shopify_order_id:
          shopifyOrderId,

        error:
          error.message,

        details:
          error.data ||
          null
      });
    }
  }
);

// ============================================================
// WEBHOOK TEST INFORMATION
// ============================================================

app.get(
  '/webhooks/orders-create',
  (req, res) => {
    res.json({
      success: true,

      message:
        'Shopify orders/create webhook endpoint is active.',

      method:
        'POST',

      topic:
        'ORDERS_CREATE',

      endpoint:
        '/webhooks/orders-create',

      status:
        'waiting_for_shopify_webhook',

      server_started_at:
        SERVER_STARTED_AT.toISOString()
    });
  }
);

// ============================================================
// 404
// ============================================================

app.use(
  (req, res) => {
    res.status(404).json({
      success: false,
      error:
        'Endpoint not found',
      path:
        req.originalUrl
    });
  }
);

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      'Unhandled error:',
      err
    );

    res.status(500).json({
      success: false,
      error:
        'Internal server error'
    });
  }
);

// ============================================================
// START SERVER
// ============================================================

app.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      '============================================'
    );

    console.log(
      '🚀 SHOPIFY → SSL WIRELESS SMS BRIDGE'
    );

    console.log(
      '============================================'
    );

    console.log(
      `🌐 Port: ${PORT}`
    );

    console.log(
      `🏪 Shopify: ${SHOP}.myshopify.com`
    );

    console.log(
      `📡 Shopify API: ${SHOPIFY_API_VERSION}`
    );

    console.log(
      '🔔 Webhook: POST /webhooks/orders-create'
    );

    console.log(
      `🕒 Server Started: ${SERVER_STARTED_AT.toISOString()}`
    );

    console.log(
      '📱 Automatic SMS: Online Store (source_name=web) only'
    );

    console.log(
      '============================================'
    );
  }
);
```
