package com.bsep.pki_system.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailSenderService {

    private final JavaMailSender mailSender;

    public EmailSenderService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    /**
     * Sends an HTML email with a clickable activation link.
     *
     * @param to Recipient email
     * @param activationLink The full activation URL
     * @param linkText Text to display instead of showing the full URL
     */
    public void sendActivationEmail(String to, String activationLink, String linkText) {
        MimeMessage message = mailSender.createMimeMessage();

        try {
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(to);
            helper.setSubject("Activate your PKI account");

            // HTML email content
            String htmlMsg = "<p>Welcome to PKI System!</p>"
                    + "<p>Click the link below to activate your account:</p>"
                    + "<a href=\"" + activationLink + "\">" + linkText + "</a>"
                    + "<p>This link will expire in 24 hours.</p>";

            helper.setText(htmlMsg, true); // true = HTML content

            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to send email to " + to, e);
        }
    }

    public void sendTemporaryPasswordEmail(String to, String tempPassword) {
        MimeMessage message = mailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(to);
            helper.setSubject("Your temporary PKI password");
            String htmlMsg = "<p>Welcome to the PKI System!</p>"
                    + "<p>Your temporary password is: <b>" + tempPassword + "</b></p>"
                    + "<p>Please log in and change it immediately.</p>";
            helper.setText(htmlMsg, true);
            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
            throw new RuntimeException("Failed to send email", e);
        }
    }
    public void sendResetPasswordEmail(String toEmail, String resetLink) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(toEmail);
            helper.setSubject("Reset Your Password");

            String content = "<p>Hello,</p>"
                    + "<p>You requested to reset your password.</p>"
                    + "<p>Click the link below to set a new password:</p>"
                    + "<p><a href=\"" + resetLink + "\">Reset Password</a></p>"
                    + "<br>"
                    + "<p>If you did not request this, please ignore this email.</p>";

            helper.setText(content, true); // true = HTML

            mailSender.send(message);

        } catch (Exception e) {
            throw new RuntimeException("Failed to send password reset email", e);
        }
    }
}