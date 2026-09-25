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

// Message template
// Available placeholders:
// {{name}}
// {{order_number}}
// {{items}}
// {{total}}
// {{currency}}

const MSG_ORDER_CREATED =
  process.env.MSG_ORDER_CREATED ||
  'Hi {{name}}, your order #{{order_number}} ({{items}}) worth {{currency}} {{total}} has been placed successfully. Thank you for shopping with us!';

const PORT = process.env.PORT || 3000;

// ============================================================
// ORDER FILTER SETTINGS
// ============================================================

// Only orders created through Shopify Online Store / Web
const ALLOWED_ORDER_SOURCE = 'web';

// Server deployment/start time
// Any order created BEFORE this time will be ignored
const DEPLOYMENT_CUTOFF = new Date();

console.log(
  '🚀 Deployment cutoff:',
  DEPLOYMENT_CUTOFF.toISOString()
);

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
// SHOPIFY TOKEN CACHE
// ============================================================

let SHOPIFY_TOKEN = null;
let SHOPIFY_EXPIRES_AT = 0;

// ============================================================
// DUPLICATE PROTECTION
// ============================================================
//
// Stores orders handled during current deployment.
//
// Important:
// This is memory-only.
// If Railway/container restarts, this Map becomes empty.
//
// Deployment cutoff protects against old orders being processed.
//

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
    const hmacHeader =
      req.get('X-Shopify-Hmac-Sha256');

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

    const receivedBuffer =
      Buffer.from(hmacHeader, 'utf8');

    const generatedBuffer =
      Buffer.from(generatedHash, 'utf8');

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

  const body =
    new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET
    });

  const response =
    await fetch(tokenUrl, {

      method: 'POST',

      headers: {
        'Content-Type':
          'application/x-www-form-urlencoded'
      },

      body: body.toString()

    });

  const data =
    await response.json();

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
    (data.expires_in || 86400) * 1000;

  console.log(
    '✅ Shopify access token obtained'
  );

  return SHOPIFY_TOKEN;
}

// ============================================================
// SHOPIFY API REQUEST
// ============================================================
//
// This is retained only for optional test/manual API endpoints.
//
// The ORDERS_CREATE webhook DOES NOT use this function.
// It uses the webhook payload directly.
//

async function shopifyRequest(
  endpoint,
  options = {}
) {

  const token =
    await getShopifyToken();

  const url =
    `https://${SHOP}.myshopify.com/admin/api/${SHOPIFY_API_VERSION}/${endpoint}`;

  const response =
    await fetch(url, {

      method:
        options.method || 'GET',

      headers: {
        'X-Shopify-Access-Token':
          token,

        'Content-Type':
          'application/json',

        ...(options.headers || {})
      },

      body:
        options.body
          ? JSON.stringify(
              options.body
            )
          : undefined

    });

  const text =
    await response.text();

  let data;

  try {

    data =
      text
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

    error.data =
      data;

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
        msisdn: phone,
        text: message,
        csms_id: csmsId
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

  let data;

  try {

    data =
      await response.json();

  } catch {

    throw new Error(
      'SSL Wireless returned invalid JSON'
    );
  }

  if (
    !response.ok ||
    data.status !== 'SUCCESS'
  ) {

    const detail =
      (
        data.smsinfo &&
        data.smsinfo[0] &&
        data.smsinfo[0]
          .status_message
      ) ||
      data.error_message ||
      data.message;

    const error =
      new Error(
        `SSL Wireless rejected the SMS: ${
          detail ||
          data.status ||
          response.status
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
//
// +8801741563884
// 8801741563884
// 01741563884
//
// Output:
//
// 8801741563884
//
// ============================================================

function normalizePhone(phone) {

  if (!phone) {
    return '';
  }

  let value =
    String(phone).trim();

  // Remove:
  // spaces
  // hyphens
  // brackets
  // plus symbol

  value =
    value.replace(
      /[\s\-()+]/g,
      ''
    );

  if (
    value.startsWith('880')
  ) {

    // Already normalized

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

  // Bangladesh mobile number
  // with country code = 13 digits

  if (
    !/^\d{13}$/.test(value)
  ) {
    return '';
  }

  return value;
}

// ============================================================
// SAFE TEMPLATE REPLACEMENT
// ============================================================

function replaceTemplate(
  template,
  values
) {

  let result =
    template;

  for (
    const [key, value]
    of Object.entries(values)
  ) {

    result =
      result.replaceAll(
        `{{${key}}}`,
        String(value ?? '')
      );

  }

  return result;
}

// ============================================================
// BUILD SMS FROM SHOPIFY WEBHOOK ORDER
// ============================================================
//
// No extra Shopify order lookup.
//
// Everything comes directly from:
// req.body
//
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

  // ----------------------------------------------------------
  // Recipient Name
  // ----------------------------------------------------------

  const recipientName =

    shipping.name ||

    billing.name ||

    (
      shopifyOrder.customer
        ?.first_name
    ) ||

    'Customer';

  // ----------------------------------------------------------
  // Recipient Phone
  // ----------------------------------------------------------

  const recipientPhone =

    shipping.phone ||

    billing.phone ||

    shopifyOrder.customer
      ?.phone ||

    shopifyOrder.phone ||

    '';

  const cleanedPhone =
    normalizePhone(
      recipientPhone
    );

  // ----------------------------------------------------------
  // Products
  // ----------------------------------------------------------

  const itemsDescription =
    items
      .map(
        (item) => {

          const title =
            item.title ||
            item.name ||
            'Product';

          const quantity =
            Number(
              item.quantity
            ) || 1;

          return (
            `${title} x${quantity}`
          );
        }
      )
      .join(', ');

  // ----------------------------------------------------------
  // Total
  // ----------------------------------------------------------

  const totalPrice =
    shopifyOrder.total_price ||
    '0.00';

  const currency =
    shopifyOrder.currency ||
    '';

  // ----------------------------------------------------------
  // Order Number
  // ----------------------------------------------------------

  const orderNumber =

    shopifyOrder.order_number ||

    shopifyOrder.name ||

    shopifyOrder.id;

  // ----------------------------------------------------------
  // Message
  // ----------------------------------------------------------

  const message =
    replaceTemplate(
      MSG_ORDER_CREATED,
      {
        name:
          recipientName,

        order_number:
          orderNumber,

        items:
          itemsDescription ||
          'your items',

        total:
          totalPrice,

        currency:
          currency
      }
    );

  return {

    phone:
      cleanedPhone,

    message,

    recipientName,

    itemsDescription,

    totalPrice,

    currency

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

      shop:
        SHOP,

      shopify_api_version:
        SHOPIFY_API_VERSION,

      allowed_order_source:
        ALLOWED_ORDER_SOURCE,

      deployment_cutoff:
        DEPLOYMENT_CUTOFF
          .toISOString(),

      webhook:
        '/webhooks/orders-create'
    });

  }
);

// ============================================================
// HEALTH
// ============================================================

app.get(
  '/health',
  (req, res) => {

    res.json({

      success: true,

      status:
        'healthy',

      timestamp:
        new Date()
          .toISOString(),

      deployment_cutoff:
        DEPLOYMENT_CUTOFF
          .toISOString()

    });

  }
);

// ============================================================
// SHOW OUTBOUND SERVER IP
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

      res
        .status(500)
        .json({

          success: false,

          error:
            error.message

        });

    }

  }
);

// ============================================================
// SHOPIFY ORDERS_CREATE WEBHOOK
// ============================================================
//
// CONDITIONS:
//
// 1. Valid Shopify HMAC
//
// 2. source_name must be "web"
//
// 3. created_at must be AFTER server deployment
//
// 4. SMS is built directly from webhook body
//
// 5. NO old order lookup
//
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
    // Verify HMAC
    // --------------------------------------------------------

    const valid =
      verifyShopifyWebhook(req);

    if (!valid) {

      console.error(
        '❌ Invalid Shopify webhook signature'
      );

      return res
        .status(401)
        .json({

          success: false,

          error:
            'Invalid Shopify webhook signature'

        });
    }

    console.log(
      '✅ Shopify webhook signature verified'
    );

    // --------------------------------------------------------
    // Order payload
    // --------------------------------------------------------

    const shopifyOrder =
      req.body;

    if (
      !shopifyOrder ||
      !shopifyOrder.id
    ) {

      console.error(
        '❌ Invalid Shopify order webhook'
      );

      return res
        .status(400)
        .json({

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

    console.log(
      '🌐 Order Source:',
      shopifyOrder.source_name ||
      'N/A'
    );

    console.log(
      '🕐 Created At:',
      shopifyOrder.created_at ||
      'N/A'
    );

    // --------------------------------------------------------
    // ACK SHOPIFY IMMEDIATELY
    // --------------------------------------------------------
    //
    // Shopify receives HTTP 200 immediately.
    //
    // SMS work continues afterward.
    //

    res
      .status(200)
      .json({

        success: true,

        received: true,

        shopify_order_id:
          shopifyOrderId

      });

    // --------------------------------------------------------
    // WEB SOURCE ONLY
    // --------------------------------------------------------

    const orderSource =
      String(
        shopifyOrder.source_name ||
        ''
      )
        .trim()
        .toLowerCase();

    if (
      orderSource !==
      ALLOWED_ORDER_SOURCE
    ) {

      console.log(
        `⏭️ Order ${shopifyOrderId} ignored`
      );

      console.log(
        `   Source: ${orderSource || 'unknown'}`
      );

      console.log(
        '   Only source_name="web" is allowed'
      );

      return;
    }

    console.log(
      '✅ Order source accepted: web'
    );

    // --------------------------------------------------------
    // DEPLOYMENT CUTOFF
    // --------------------------------------------------------

    if (
      !shopifyOrder.created_at
    ) {

      console.warn(
        `⚠️ Order ${shopifyOrderId} has no created_at`
      );

      console.warn(
        '   SMS skipped'
      );

      return;
    }

    const orderCreatedAt =
      new Date(
        shopifyOrder.created_at
      );

    if (
      Number.isNaN(
        orderCreatedAt.getTime()
      )
    ) {

      console.warn(
        `⚠️ Invalid created_at for order ${shopifyOrderId}`
      );

      return;
    }

    console.log(
      '📅 Order time:',
      orderCreatedAt
        .toISOString()
    );

    console.log(
      '🚀 Deployment:',
      DEPLOYMENT_CUTOFF
        .toISOString()
    );

    // Ignore anything older than this deployment

    if (
      orderCreatedAt <
      DEPLOYMENT_CUTOFF
    ) {

      console.log(
        `⏭️ OLD ORDER ${shopifyOrderId} ignored`
      );

      console.log(
        '   Reason: created before deployment'
      );

      return;
    }

    console.log(
      '✅ Order passed deployment cutoff'
    );

    // --------------------------------------------------------
    // DUPLICATE PROTECTION
    // --------------------------------------------------------

    if (
      submittedOrders.has(
        shopifyOrderId
      )
    ) {

      console.log(
        `⚠️ Order ${shopifyOrderId} already processed`
      );

      return;
    }

    // Lock immediately before async SMS call

    submittedOrders.set(
      shopifyOrderId,
      {
        status:
          'processing',

        started_at:
          new Date()
            .toISOString()
      }
    );

    // --------------------------------------------------------
    // BUILD SMS DIRECTLY FROM WEBHOOK
    // --------------------------------------------------------

    const {
      phone,
      message,
      recipientName,
      itemsDescription,
      totalPrice,
      currency
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
      '💰 Total:',
      currency,
      totalPrice
    );

    console.log(
      '💬 Message:',
      message
    );

    // --------------------------------------------------------
    // INVALID PHONE
    // --------------------------------------------------------

    if (!phone) {

      console.warn(
        `⚠️ No valid BD phone for order ${shopifyOrderId}`
      );

      submittedOrders.set(
        shopifyOrderId,
        {

          success: false,

          status:
            'skipped',

          reason:
            'invalid_phone',

          shopify_order_id:
            shopifyOrderId

        }
      );

      return;
    }

    // --------------------------------------------------------
    // SMS ID
    // --------------------------------------------------------

    const csmsId =
      `${shopifyOrderId}-${Date.now()}`
        .slice(0, 20);

    // --------------------------------------------------------
    // SEND SMS
    // --------------------------------------------------------

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

        success:
          true,

        status:
          'sent',

        shopify_order_id:
          shopifyOrder.id,

        shopify_order_name:
          shopifyOrder.name,

        source:
          orderSource,

        order_created_at:
          shopifyOrder.created_at,

        deployment_cutoff:
          DEPLOYMENT_CUTOFF
            .toISOString(),

        phone,

        csms_id:
          csmsId,

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

          success:
            false,

          status:
            'failed',

          shopify_order_id:
            shopifyOrderId,

          error:
            error.message,

          details:
            error.data ||
            null

        }
      );
    }

  }
);

// ============================================================
// TEST SHOPIFY CONNECTION
// ============================================================
//
// Optional endpoint.
// Does NOT run automatically.
//

app.get(
  '/api/test/shopify',
  async (req, res) => {

    try {

      const data =
        await shopifyRequest(
          'shop.json'
        );

      res.json({

        success:
          true,

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

      res
        .status(
          error.status ||
          500
        )
        .json({

          success:
            false,

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
//
// Example:
//
// /api/test/sms?phone=01741563884
//
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

            success:
              false,

            error:
              'Pass a valid BD phone number as ?phone=01XXXXXXXXX'

          });
      }

      const result =
        await sendSms(

          phone,

          'This is a test message from your Shopify SMS bridge.',

          `test-${Date.now()}`
            .slice(0, 20)

        );

      res.json({

        success:
          true,

        message:
          'Test SMS sent',

        phone,

        sms_response:
          result

      });

    } catch (error) {

      console.error(
        'SMS test error:',
        error.data ||
        error.message
      );

      res
        .status(500)
        .json({

          success:
            false,

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
// WEBHOOK STATUS
// ============================================================

app.get(
  '/webhooks/orders-create',

  (req, res) => {

    res.json({

      success:
        true,

      message:
        'Shopify orders/create webhook endpoint is active.',

      method:
        'POST',

      topic:
        'ORDERS_CREATE',

      endpoint:
        '/webhooks/orders-create',

      allowed_source:
        'web',

      deployment_cutoff:
        DEPLOYMENT_CUTOFF
          .toISOString(),

      old_orders:
        'ignored',

      shopify_order_lookup:
        false,

      status:
        'waiting_for_new_web_orders'

    });

  }
);

// ============================================================
// CURRENT DEPLOYMENT INFO
// ============================================================

app.get(
  '/api/deployment',

  (req, res) => {

    res.json({

      success:
        true,

      deployment_cutoff:
        DEPLOYMENT_CUTOFF
          .toISOString(),

      allowed_order_source:
        ALLOWED_ORDER_SOURCE,

      processed_orders_this_deployment:
        submittedOrders.size

    });

  }
);

// ============================================================
// 404
// ============================================================

app.use(
  (req, res) => {

    res
      .status(404)
      .json({

        success:
          false,

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
  (err, req, res, next) => {

    console.error(
      'Unhandled error:',
      err
    );

    if (
      res.headersSent
    ) {
      return next(err);
    }

    res
      .status(500)
      .json({

        success:
          false,

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
      '🌐 Allowed order source: web'
    );

    console.log(
      `⏱️ Deployment cutoff: ${DEPLOYMENT_CUTOFF.toISOString()}`
    );

    console.log(
      '🔔 Webhook: POST /webhooks/orders-create'
    );

    console.log(
      '📦 Previous orders: NOT fetched'
    );

    console.log(
      '📨 SMS data source: webhook payload only'
    );

    console.log(
      '============================================'
    );

  }
);
