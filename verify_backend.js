const fetch = require('node-fetch'); // You might need to install this if running in node env without global fetch
// Or use built-in fetch if Node 18+

const BASE_URL = 'http://localhost:3000/api';

async function testBackend() {
    console.log('--- Starting Backend Verification ---');

    // 1. Register
    console.log('\n--- Testing Registration ---');
    const username = `testuser_${Date.now()}`;
    const password = 'password123';

    let res = await fetch(`${BASE_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    let data = await res.json();
    console.log(`Register status: ${res.status} - ${JSON.stringify(data)}`);

    if (res.status !== 201) return;

    // 2. Login
    console.log('\n--- Testing Login ---');
    res = await fetch(`${BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    data = await res.json();
    console.log(`Login status: ${res.status}`);

    const token = data.token;
    if (!token) {
        console.error('No token received');
        return;
    }
    console.log('Received Token');

    // 3. Create Conversation
    console.log('\n--- Testing Create Conversation ---');
    res = await fetch(`${BASE_URL}/conversations`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        }
    });
    data = await res.json();
    console.log(`Create Conversation status: ${res.status}`);
    const conversationId = data.id;
    console.log(`Conversation ID: ${conversationId}`);

    // 4. Send Message (Expect fail or placeholder if no API key)
    console.log('\n--- Testing Send Message ---');
    res = await fetch(`${BASE_URL}/conversations/${conversationId}/messages`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ content: 'Hello, are you there?' })
    });

    // We expect this might fail due to missing API Key, which is correct behavior for now
    data = await res.json();
    console.log(`Send Message status: ${res.status} - ${JSON.stringify(data)}`);

    if (data.error && data.error.includes('OpenRouter API Key is missing')) {
        console.log('SUCCESS: Correctly identified missing API Key.');
    } else if (res.status === 200) {
        console.log('SUCCESS: Message sent successfully (API Key was present?).');
    } else {
        console.log('Observation: Request failed as expected or unexpected error.');
    }

    // 5. Check Health
    console.log('\n--- Testing Health ---');
    res = await fetch('http://localhost:3000/health');
    data = await res.json();
    console.log(`Health: ${JSON.stringify(data)}`);
}

testBackend();
