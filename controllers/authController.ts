// controllers/authController.js
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { prisma } from '../config/prisma.js';
import { sendVerificationEmail, sendPasswordResetEmail } from '../services/emailService.js';
import crypto from 'crypto';

class AuthController {
  // Generate JWT token
  generateToken(userId) {
    return jwt.sign(
      { id: userId },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '30d' }
    );
  }

  // Create and send JWT token in response
  sendTokenResponse(user, statusCode, res) {
    const token = this.generateToken(user.id);
    
    // Remove password from output
    user.password = undefined;
    
    res.status(statusCode).json({
      success: true,
      token,
      user
    });
  }

  // User signup
  async signup(req, res) {
    try {
      const { email, password, userType, firstName, lastName, phone } = req.body;
      
      // Check if user already exists
      const existingUser = await prisma.user.findUnique({ where: { email } });
      if (existingUser) {
        return res.status(400).json({
          success: false,
          error: 'Email already registered'
        });
      }

      // Create verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');

      // Create user
      const hashedPassword = await bcrypt.hash(password, 12);
      const user = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          userType,
          firstName,
          lastName,
          phone,
          verificationToken,
          lastLogin: new Date()
        }
      });

      // Send verification email
      await sendVerificationEmail(user.email, verificationToken);

      // Send token response
      this.sendTokenResponse(user, 201, res);
      
    } catch (error) {
      console.error('Signup error:', error);
      res.status(500).json({ 
        success: false,
        error: 'Failed to create account' 
      });
    }
  }

  // User signin
  async signin(req, res) {
    try {
      const { email, password } = req.body;
      
      // Validate email & password
      if (!email || !password) {
        return res.status(400).json({ 
          success: false,
          error: 'Please provide email and password' 
        });
      }
      
      // Check for user
      const user = await prisma.user.findUnique({ where: { email } });
      
      if (!user) {
        return res.status(401).json({ 
          success: false,
          error: 'Invalid credentials' 
        });
      }
      
      // Check if user is active
      if (!user.isActive) {
        return res.status(401).json({ 
          success: false,
          error: 'Account has been deactivated' 
        });
      }
      
      
      // Check password
      const isPasswordMatch = await bcrypt.compare(password, user.password);
      
      if (!isPasswordMatch) {
        return res.status(401).json({ 
          success: false,
          error: 'Invalid credentials' 
        });
      }
      
      // Update last login
      const updatedUser = await prisma.user.update({
        where: { id: user.id },
        data: { lastLogin: new Date() }
      });

      // Send token response
      this.sendTokenResponse(updatedUser, 200, res);
      
    } catch (error) {
      console.error('Signin error:', error);
      res.status(500).json({ 
        success: false,
        error: 'Failed to sign in' 
      });
    }
  }

  // Get current user
  async getMe(req, res) {
    try {
      const user = await prisma.user.findUnique({ where: { id: req.user.id } });
      
      res.status(200).json({
        success: true,
        user
      });
    } catch (error) {
      res.status(500).json({ 
        success: false,
        error: 'Failed to get user data' 
      });
    }
  }

  // Sign out (client-side token removal, but we can add token blacklisting)
  async signout(req, res) {
    // In a production app, you might want to implement token blacklisting
    // For now, we'll just send a success response
    res.status(200).json({
      success: true,
      message: 'Signed out successfully'
    });
  }

  // Verify email
  async verifyEmail(req, res) {
    try {
      const { token } = req.params;
      
      const user = await prisma.user.findFirst({ where: { verificationToken: token } });
      
      if (!user) {
        return res.status(400).json({ 
          success: false,
          error: 'Invalid verification token' 
        });
      }
      

      await prisma.user.update({
        where: { id: user.id },
        data: { isVerified: true, verificationToken: null }
      });
      res.status(200).json({
        success: true,
        message: 'Email verified successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to verify email'
      });
    }
  }

  // Forgot password
  async forgotPassword(req, res) {
    try {
      const { email } = req.body;
      
      const user = await prisma.user.findUnique({ where: { email } });
      
      if (!user) {
        return res.status(404).json({ 
          success: false,
          error: 'No user found with that email' 
        });
      }
      
      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      
      await prisma.user.update({
        where: { id: user.id },
        data: {
          passwordResetToken: resetToken,
          passwordResetExpires: new Date(Date.now() + 30 * 60 * 1000)
        }
      });
      
      // Send reset email
      await sendPasswordResetEmail(user.email, resetToken);
      
      res.status(200).json({
        success: true,
        message: 'Password reset email sent'
      });
    } catch (error) {
      res.status(500).json({ 
        success: false,
        error: 'Failed to send reset email' 
      });
    }
  }

  // Reset password
  async resetPassword(req, res) {
    try {
      const { token } = req.params;
      const { password } = req.body;
      
      const user = await prisma.user.findFirst({
        where: {
          passwordResetToken: token,
          passwordResetExpires: { gt: new Date() }
        }
      });
      
      if (!user) {
        return res.status(400).json({ 
          success: false,
          error: 'Invalid or expired reset token' 
        });
      }

      const hashed = await bcrypt.hash(password, 12);
      const updated = await prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashed,
          passwordResetToken: null,
          passwordResetExpires: null
        }
      });

      // Send token response
      this.sendTokenResponse(updated, 200, res);
      
    } catch (error) {
      res.status(500).json({ 
        success: false,
        error: 'Failed to reset password' 
      });
    }
  }
}

// Export an instance of the controller
export default new AuthController();
