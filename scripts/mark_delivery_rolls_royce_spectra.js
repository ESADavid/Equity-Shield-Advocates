/**
 * Script to mark the Rolls Royce Spectra Black Badge as delivered
 * using the existing delivery API endpoint in the earnings dashboard system.
 * 
 * This script sends a POST request to /api/delivery/mark-delivered with the required details.
 */

const fetch = require('node-fetch');

async function markDelivery() {
  const apiUrl = 'http://localhost:4000/api/delivery/mark-delivered'; // Adjust if server runs on different host/port

  const deliveryDetails = {
    vin: 'SCATK4CO4SU229567',
    deliveryDate: new Date().toISOString(), // Use current date/time or specify a date string
    deliveryAddress: '1316 South Tryon St., Charlotte, NC 28203'
  };

  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from('admin:securepassword').toString('base64') // Basic auth as per server setup
      },
      body: JSON.stringify(deliveryDetails)
    });

    const result = await response.json();

    if (response.ok) {
      console.log('Delivery marked successfully:', result);
    } else {
      console.error('Failed to mark delivery:', result.error);
    }
  } catch (error) {
    console.error('Error during delivery request:', error);
  }
}

markDelivery();
