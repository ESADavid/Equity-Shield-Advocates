/**
 * USER ACCEPTANCE TEST
 * Tests complete user workflows from end-user perspective
 */

import CitizenPortalService from '../../services/citizenPortalService.js';
import PartnerCoordinationService from '../../services/partnerCoordinationService.js';
import MultiChannelNotificationService from '../../services/multiChannelNotificationService.js';

describe('User Acceptance Tests - Complete Workflows', () => {
  describe('New Citizen Onboarding Workflow', () => {
    test('Complete citizen journey: Registration → Verification → UBI Enrollment → Education', async () => {
      const portalService = new CitizenPortalService();
      
      // Step 1: Register
      const registration = await portalService.registerCitizen({
        firstName: 'UAT',
        lastName: 'Citizen',
        dateOfBirth: '1990-01-01',
        gender: 'male',
        nationality: 'US',
        ssn: '123-45-6789',
        email: 'uat@citizen.com',
        phone: '+1234567890',
        address: {
          street: '123 UAT St',
          city: 'Test City',
          state: 'TS',
          country: 'USA',
          postalCode: '12345'
        }
      });

      expect(registration.success).toBe(true);
      const citizenId = registration.citizenId;

      // Step 2: Verify account (simulated)
      const citizen = portalService.citizens.get(citizenId);
      citizen.verificationStatus = 'verified';

      // Step 3: Enroll in UBI
      const ubiEnrollment = await portalService.enrollInUBI(citizenId, {
        paymentMethod: 'direct_deposit',
        bankAccount: {
          accountNumber: '1234567890',
          routingNumber: '987654321'
        }
      });

      expect(ubiEnrollment.success).toBe(true);

      // Step 4: Enroll in Education
      const eduEnrollment = await portalService.enrollInCourse(citizenId, 'COURSE-001');

      expect(eduEnrollment.success).toBe(true);

      // Step 5: Verify profile completeness
      const profile = portalService.getCitizenProfile(citizenId);

      expect(profile.success).toBe(true);
      expect(profile.summary.ubiEnrolled).toBe(true);
      expect(profile.summary.educationEnrolled).toBe(true);
    });
  });

  describe('Partner Collaboration Workflow', () => {
    test('Complete partner journey: Onboarding → Activation → Project Assignment → Completion', async () => {
      const partnerService = new PartnerCoordinationService();

      // Step 1: Onboard Partner
      const onboarding = await partnerService.onboardPartner({
        name: 'UAT Partner Corp',
        type: 'corporate',
        contact: {
          primaryContact: {
            name: 'UAT Contact',
            email: 'contact@uatpartner.com',
            phone: '+1234567890'
          }
        },
        contract: {
          startDate: new Date().toISOString(),
          duration: 12,
          value: 100000
        }
      }, 'uat-admin');

      expect(onboarding.success).toBe(true);
      const partnerId = onboarding.partnerId;

      // Step 2: Complete onboarding workflow
      const workflow = Array.from(partnerService.workflows.values())
        .find(w => w.partnerId === partnerId);

      workflow.steps.forEach(step => {
        if (step.required) {
          partnerService.updateWorkflowStep(workflow.workflowId, step.stepId, 'completed', 'uat-admin');
        }
      });

      // Step 3: Assign Project
      const projectAssignment = partnerService.assignProject(partnerId, {
        name: 'UAT Project',
        description: 'User acceptance test project',
        type: 'development',
        priority: 'high',
        budget: 50000,
        personnel: 5
      }, 'uat-admin');

      expect(projectAssignment.success).toBe(true);

      // Step 4: Complete Project
      const completion = partnerService.updateProjectStatus(
        projectAssignment.projectId,
        'completed',
        { notes: 'Project completed successfully', onTime: true, qualityScore: 95 },
        'uat-admin'
      );

      expect(completion.success).toBe(true);

      // Step 5: Rate Performance
      const rating = partnerService.updatePerformanceRating(partnerId, {
        rating: 4.5,
        comments: 'Excellent work',
        category: 'project-delivery',
        quality: 95,
        timeliness: 90,
        communication: 92,
        professionalism: 94
      }, 'uat-admin');

      expect(rating.success).toBe(true);
    });
  });

  describe('Notification Delivery Workflow', () => {
    test('Complete notification journey: Send → Track → Verify Delivery', async () => {
      const notificationService = new MultiChannelNotificationService();

      // Step 1: Send Notification
      const send = await notificationService.sendNotification({
        userId: 'uat-user',
        templateId: 'ubi-payment-success',
        channels: ['email', 'push', 'in-app'],
        data: {
          citizenName: 'UAT User',
          amount: '1000',
          paymentDate: new Date().toISOString(),
          reference: 'UAT-REF-001'
        }
      });

      expect(send.success).toBe(true);
      const notificationId = send.notificationId;

      // Step 2: Verify Notification Details
      const notification = notificationService.getNotification(notificationId);

      expect(notification.success).toBe(true);
      expect(notification.notification.status).toBe('sent');

      // Step 3: Check Delivery Status
      expect(notification.notification.deliveryStatus).toBeDefined();
      expect(Object.keys(notification.notification.deliveryStatus).length).toBeGreaterThan(0);
    });
  });

  describe('Service Request Workflow', () => {
    test('Complete service request journey: Submit → Track → Resolution', async () => {
      const portalService = new CitizenPortalService();

      // Setup: Create citizen
      const registration = await portalService.registerCitizen({
        firstName: 'Service',
        lastName: 'Requester',
        dateOfBirth: '1990-01-01',
        gender: 'male',
        nationality: 'US',
        ssn: '123-45-6789',
        email: 'service@test.com',
        phone: '+1234567890'
      });

      const citizenId = registration.citizenId;

      // Step 1: Submit Service Request
      const request = await portalService.createServiceRequest(citizenId, {
        type: 'support',
        category: 'technical',
        subject: 'UAT Service Request',
        description: 'Testing service request workflow',
        priority: 'medium'
      });

      expect(request.success).toBe(true);
      const requestId = request.requestId;

      // Step 2: Track Request
      const requestDetails = portalService.getServiceRequest(requestId);

      expect(requestDetails.success).toBe(true);
      expect(requestDetails.serviceRequest.status).toBe('submitted');

      // Step 3: Verify Request in Citizen Profile
      const profile = portalService.getCitizenProfile(citizenId);

      expect(profile.success).toBe(true);
      expect(profile.summary.pendingRequests).toBeGreaterThan(0);
    });
  });
});
