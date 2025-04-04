const nodemailer = require('nodemailer');

// Configure your Gmail with App Password
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'xxxxx@gmail.com', // Your Gmail
        pass: 'xxxx xxxx xxxx xxxx' // App Password (not regular password)
    }
});

// Student data
const students = [
    {
        name: "John Doe",
        std: "2nd Grade",
        score: 9
    },
    {
        name: "Alice Johnson",
        std: "1st Grade",
        score:10
    },
    {
        name: "Jane Smith", 
        std: "1st Grade",
        score: 7 // Won't trigger email (score ≤ 8)
    }
];

// List of NGO emails
const ngoEmails = [
    "xx@gmail.com",
    "yy@gmail.com",
    "zz@gmail.com"
];

async function sendHighScoreNotifications() {
    for (const student of students) {
        if (student.score > 8) {
            try {
                // Send to each NGO
                for (const ngoEmail of ngoEmails) {
                    const mailOptions = {
                        from: '"School Admin" <your.personal@gmail.com>',
                        to: ngoEmail,
                        subject: `High Score Alert: ${student.name} (${student.score}/10)`,
                        html: `
                            <h3>Student Performance Notification</h3>
                            <p><strong>Name:</strong> ${student.name}</p>
                            <p><strong>Class:</strong> ${student.std}</p>
                            <p><strong>Score:</strong> ${student.score}/10</p>
                            <p>This student qualifies for your scholarship program.</p>
                        `,
                        text: `High Score Alert:\n\nStudent: ${student.name}\nClass: ${student.std}\nScore: ${student.score}/10\n\nAction required: Please consider for your programs.`
                    };

                    const info = await transporter.sendMail(mailOptions);
                    console.log(`Sent to ${ngoEmail} for ${student.name}`);
                }
            } catch (error) {
                console.error(`Failed to send for ${student.name}:`, error);
            }
        } else {
            console.log(`No email sent for ${student.name} (score ${student.score} ≤ 8)`);
        }
    }
}

// Execute
sendHighScoreNotifications()
    .then(() => console.log("✅ All notifications processed"))
    .catch(err => console.error("❌ Process failed:", err));
