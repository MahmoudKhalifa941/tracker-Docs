# Tracker Platform — Full API Documentation

> **Base URL:** `https://api.bloomington.pro/api`
> **Auth:** Bearer Token (Laravel Sanctum)
> **Content-Type:** `application/json`
> **Last Updated:** February 11, 2026
> **Purpose:** Definitive reference for frontend engineers to connect with all backend endpoints.

---

## Table of Contents

1. [Authentication & General Info](#1-authentication--general-info)
2. [Public Endpoints (No Auth)](#2-public-endpoints)
3. [Shared Authenticated Endpoints](#3-shared-authenticated-endpoints)
4. [Student Endpoints](#4-student-endpoints)
5. [Parent Endpoints](#5-parent-endpoints)
6. [Teacher Endpoints](#6-teacher-endpoints)
7. [Principal Endpoints](#7-principal-endpoints)
8. [HOD Endpoints](#8-hod-endpoints)
9. [Admin Endpoints](#9-admin-endpoints)
10. [Standard Response Patterns](#10-standard-response-patterns)

---

## 1. Authentication & General Info

### Headers (All Authenticated Requests)

```
Authorization: Bearer {token}
Accept: application/json
Content-Type: application/json
```

### Rate Limits

| Context | Limit |
|---|---|
| Login | 5 attempts/minute per IP+email |
| Standard API | 60 requests/minute |
| AI Generation | 10 requests/minute, 100/day per user |
| File Uploads | 5 uploads/hour |

---

### `POST /login`

Login and receive a bearer token.

**Request Body:**

```json
{
  "email": "user@school.com",
  "password": "secret123",
  "device_name": "iPhone 15 Pro" // optional
}
```

**Success Response (200):**

```json
{
  "access_token": "1|abc123...",
  "token_type": "Bearer",
  "user": {
    "id": 1,
    "name": "Ahmed Ali",
    "email": "user@school.com",
    "avatar": "https://...",
    "school_id": 5,
    "classroom_id": 12,
    "role": "student",
    "hod_subject_ids": [],
    "hod_subjects": []
  }
}
```

**Error Responses:**

| Code | `code` field | Meaning |
|---|---|---|
| 422 | — | Invalid credentials |
| 429 | — | Too many login attempts |
| 403 | `SCHOOL_NOT_FOUND` | User's school doesn't exist |
| 403 | `SCHOOL_INACTIVE` | School is deactivated |
| 403 | `SUBSCRIPTION_EXPIRED` | School subscription expired |

---

### `POST /logout`
**Auth Required.** Revokes the current token.

**Response (200):**
```json
{ "message": "Logged out successfully" }
```

---

### `GET /user`
**Auth Required.** Get current authenticated user profile.

**Response (200):** Same `user` object as login response.

---

## 2. Public Endpoints

No authentication required.

### `GET /platform-settings/public`
Get public platform settings (branding, theme, etc.).

### `GET /translations/{locale}`
Get translations for a locale (e.g. `ar`, `en`).

### `GET /locales`
Get list of active locales.

### `GET /plans/public`
Get public subscription plans for pricing page.

---

## 3. Shared Authenticated Endpoints

These endpoints are shared across multiple roles. Auth required.

---

### 3.1 Notifications

#### `POST /notifications/register`
Register push notification token.

**Request Body:**
```json
{
  "token": "ExponentPushToken[xxx]",
  "platform": "ios" // "ios" | "android" | "web"
}
```

#### `POST /notifications/unregister`
Unregister push notification token.

**Request Body:**
```json
{ "token": "ExponentPushToken[xxx]" }
```

---

### 3.2 Chat / Messaging System

All routes under `/chat` prefix.

#### `GET /chat/conversations`
List all conversations for current user. Paginated (20/page).

**Response (200):**
```json
{
  "data": [
    {
      "id": 1,
      "type": "direct",
      "title": null,
      "created_at": "2026-01-15T...",
      "updated_at": "2026-02-10T...",
      "participants": [
        { "id": 1, "user": { "id": 5, "name": "Teacher Ali", "avatar": "..." } }
      ],
      "latest_message": {
        "id": 50, "body": "Hello!", "type": "text", "created_at": "..."
      }
    }
  ],
  "current_page": 1,
  "last_page": 3,
  "per_page": 20,
  "total": 55
}
```

#### `POST /chat/conversations`
Create a new conversation.

**Request Body:**
```json
{
  "participants": [5, 12],
  "type": "direct",    // "direct" | "group"
  "title": "Study Group" // optional, for group chats
}
```

**Response (201):** Conversation object with participants.

#### `GET /chat/conversations/{conversationId}`
Get a single conversation with participants.

#### `GET /chat/conversations/{conversationId}/messages`
Get messages in a conversation. Paginated (50/page), newest first.

**Response (200):**
```json
{
  "data": [
    {
      "id": 100,
      "body": "Hello!",
      "type": "text",
      "attachment_url": null,
      "sender": { "id": 5, "name": "Ahmed", "avatar": "..." },
      "created_at": "2026-02-10T14:30:00Z"
    }
  ],
  "current_page": 1,
  "last_page": 2,
  "per_page": 50,
  "total": 75
}
```

#### `POST /chat/conversations/{conversationId}/messages`
Send a message.

**Request Body:**
```json
{
  "body": "Hello teacher!",
  "type": "text",              // "text" | "image" | "file"
  "attachment_url": null       // optional URL for files
}
```

**Response (201):** Message object with sender.

#### `POST /chat/conversations/{conversationId}/read`
Mark conversation as read.

**Response (200):**
```json
{ "status": "success" }
```

---

### 3.3 Dashboard

#### `GET /dashboard/stats`
General dashboard statistics (role-aware).

---

### 3.4 CRUD Resources

#### Schools: `GET|POST /schools`, `GET|PUT|DELETE /schools/{id}`
#### Classrooms: `GET|POST /classrooms`, `GET|PUT|DELETE /classrooms/{id}`
#### Subjects: `GET|POST /subjects`, `GET|PUT|DELETE /subjects/{id}`
#### Users: `GET|POST /users`, `GET|PUT|DELETE /users/{id}`

Standard Laravel API Resource pattern with pagination.

---

### 3.5 Analytics

#### `GET /analytics`
School-wide analytics.

#### `GET /analytics/cohorts`
Cohort analytics data.

#### `GET /analytics/cohort/evolution`
Cohort evolution comparison.

#### `GET /analytics/risk/school`
AI Risk analytics for school.

#### `GET /analytics/risk/{studentId}`
Individual student risk assessment.

---

### 3.6 Longitudinal Timeline

#### `GET /students/{id}/timeline`
Student academic timeline across years.

#### `POST /students/{id}/timeline/refresh`
Refresh timeline snapshot.

#### `GET /students/{id}/forecast`
AI-powered grade forecast.

---

### 3.7 Subscriptions & Features

#### `GET /subscriptions/current` — current subscription
#### `GET /subscriptions/status` — subscription status
#### `POST /subscriptions` — subscribe
#### `POST /subscriptions/{id}/renew` — renew
#### `POST /subscriptions/{id}/cancel` — cancel
#### `POST /subscriptions/{id}/upgrade` — upgrade

#### `GET /features/available` — available features
#### `GET /features/usage` — feature usage
#### `GET /features/check/{featureName}` — check specific feature access

---

### 3.8 Error Reporting

#### `POST /support/report-error`
Report a client-side error (rate-limited: uploads tier).

---

### 3.9 AI Feedback

#### `POST /ai/feedback/{generationId}`
Submit feedback for an AI generation.

---

### 3.10 AI Content Generation (Shared)

#### `POST /ai/generate-reading`
Generate AI reading material (rate-limited: ai tier).

---

## 4. Student Endpoints

**Prefix:** `/student`
**Middleware:** `auth:sanctum`, `SetLanguage`, `EnsureStudentScope`

---

### 4.1 Dashboard

#### `GET /student/dashboard`
Get student dashboard statistics.

**Response (200):**
```json
{
  "pending_assignments": 5,
  "completed_assignments": 12,
  "next_deadline": {
    "title": "Math Homework Ch.5",
    "date": "2026-02-15T23:59:59+00:00"
  },
  "recent_activity": [
    {
      "id": 45,
      "type": "submission",
      "assignment": "Science Lab Report",
      "status": "graded",
      "score": 85,
      "date": "2026-02-10T14:30:00+00:00"
    }
  ]
}
```

---

### 4.2 Profile

#### `GET /student/profile`
Get student profile.

#### `PATCH /student/profile`
Update student profile.

**Request Body:**
```json
{
  "name": "Ahmed Ali",
  "avatar": "base64..." // or URL
}
```

---

### 4.3 Subjects

#### `GET /student/subjects`
List student subjects.

#### `GET /student/subjects/{id}`
Get subject details.

---

### 4.4 Assignments

#### `GET /student/assignments`
List student assignments. Paginated.

**Query Params:** `per_page` (default: 20)

**Response (200):**
```json
{
  "data": [
    {
      "id": 1,
      "title": "Math Homework",
      "subject": "Mathematics",
      "due_date": "2026-02-15T23:59:59Z",
      "status": "pending",   // "pending" | "submitted" | "graded"
      "grade": null,
      "type": "homework"
    }
  ],
  "current_page": 1,
  "last_page": 2,
  "per_page": 20,
  "total": 30
}
```

#### `GET /student/assignments/{id}`
Get assignment details with questions and existing submission.

**Response (200):**
```json
{
  "assignment": {
    "id": 1,
    "title": "Math Homework",
    "status": "published",
    "due_date": "2026-02-15T...",
    "subject": { "id": 3, "name": "Mathematics" },
    "questions": [
      {
        "id": 10,
        "question_text": "Solve: 2x + 5 = 15",
        "type": "short_answer",
        "options": null,
        "points": 10,
        "order": 1
      }
    ]
  },
  "submission": null  // or submission object if already submitted
}
```

#### `POST /student/assignments/{id}/submit`
Submit an assignment.

**Request Body:**
```json
{
  "content": "My essay text here...",      // optional, free-text content
  "answers": [                              // optional, structured answers
    {
      "question_id": 10,
      "answer_text": "x = 5"
    }
  ]
}
```

**Response (200):**
```json
{ "message": "Assignment submitted successfully" }
```

**Error:** `403` if already graded. `422` if student not in classroom.

---

### 4.5 Outcomes Analytics

#### `GET /student/outcomes`
Get student learning outcomes data.

---

### 4.6 Notifications

#### `GET /student/notifications`
List notifications.

#### `POST /student/notifications/mark-all-read`
Mark all as read.

#### `PATCH /student/notifications/{id}/read`
Mark single notification as read.

#### `DELETE /student/notifications/{id}`
Delete notification.

---

### 4.7 Reading Platform

#### `GET /student/reading`
List all reading materials.

#### `GET /student/reading/recommendations`
Get AI-powered reading recommendations.

#### `GET /student/reading/{id}`
Show reading material details.

#### `GET /student/reading/{id}/questions`
Get comprehension questions.

#### `POST /student/reading/{id}/submit`
Submit reading answers.

---

### 4.8 Lesson Library

#### `GET /student/library/lessons`
List lessons.

#### `GET /student/library/lessons/{id}`
Get lesson details.

#### `GET /student/library/lessons/{id}/questions`
Get lesson questions.

#### `POST /student/library/lessons/{id}/track`
Track lesson view.

#### `POST /student/library/lessons/{id}/complete`
Mark lesson as complete.

---

### 4.9 Assessments (Baseline/Term)

#### `GET /student/assessments`
List available assessments.

#### `POST /student/assessments/{id}/start`
Start an assessment attempt.

#### `GET /student/attempts/{id}`
Get attempt details (questions, progress).

#### `POST /student/attempts/{id}/submit`
Submit assessment attempt.

---

### 4.10 Standardized Assessments

#### `GET /student/standardized`
List standardized assessments.

#### `POST /student/standardized/{id}/start`
Start standardized assessment.

#### `POST /student/standardized/{id}/save-progress`
Save progress (partial save).

#### `POST /student/standardized/attempts/{id}/submit`
Submit standardized attempt.

#### `GET /student/standardized/{id}/result`
Get standardized assessment result.

---

### 4.11 Progress & Analytics

#### `GET /student/progress`
Get overall progress report.

#### `GET /student/progress/skills`
Get skills mastery progress.

#### `GET /student/feedback`
Get teacher feedback.

---

### 4.12 Gamification

#### `GET /student/gamification/stats`
Get XP, Level, Streak.

#### `GET /student/gamification/badges`
Get earned and available badges.

#### `GET /student/gamification/leaderboard`
Get class leaderboard.

#### `GET /student/gamification/leaderboards`
Get multi-type leaderboards (class, skill, participation, streak).

**Query Params:** `type` (default returns all types)

#### `GET /student/gamification/feed`
Classroom activity feed.

#### `GET /student/gamification/rewards`
List student rewards.

#### `GET /student/gamification/rewards/{id}`
Single reward details.

#### `GET /student/gamification/challenges`
Get active challenges with progress.

#### `POST /student/gamification/challenges/{id}/activate`
Activate a challenge.

#### `GET /student/gamification/cheers`
Get received cheers.

#### `POST /student/gamification/cheers`
Send a cheer to a peer.

**Request Body:**
```json
{
  "to_student_id": 15,
  "cheer_type": "congrats", // "congrats" | "encourage" | "celebrate"
  "message": "Great job!"   // optional
}
```

#### `GET /student/gamification/customization`
Get avatars, themes, and current customization.

#### `POST /student/gamification/customization`
Update avatar/theme.

**Request Body:**
```json
{
  "avatar_id": 3,
  "theme_id": 2,
  "bio": "Love Math!"
}
```

#### `GET /student/gamification/motivation`
Get motivational message.

---

### 4.13 Shop

#### `GET /student/gamification/shop`
List shop items.

#### `POST /student/gamification/shop/purchase`
Purchase a shop item.

**Request Body:**
```json
{ "item_id": 5 }
```

---

### 4.14 Duels (Learning Battles)

#### `GET /student/duels`
List duels.

#### `POST /student/duels/challenge`
Challenge another student.

**Request Body:**
```json
{
  "opponent_id": 15,
  "subject_id": 3
}
```

#### `POST /student/duels/{duelId}/accept`
Accept a duel challenge.

#### `POST /student/duels/{duelId}/submit`
Submit duel answers.

---

### 4.15 Wellbeing

#### `GET /student/wellbeing/dashboard`
Get wellbeing dashboard data.

#### `POST /student/wellbeing/check-in`
Daily mood check-in.

**Request Body:**
```json
{
  "mood_score": 4,            // 1-5
  "mood_label": "happy",      // optional
  "notes": "Feeling good",    // optional, max 280 chars
  "stress_score": 2,          // 1-5
  "confidence_score": 4,      // 1-5
  "motivation_score": 5       // 1-5
}
```

#### `GET /student/wellbeing/moods`
Get mood entries.

**Query Params:** `days` (default: 7)

#### `GET /student/wellbeing/status`
Get current wellbeing status.

#### `GET /student/wellbeing/summary/weekly`
Get weekly wellbeing summary.

#### `GET /student/wellbeing/assistant`
Get wellbeing assistant prompts.

#### `POST /student/wellbeing/assistant`
Send message to wellbeing chatbot.

**Request Body:**
```json
{ "message": "I feel stressed about the exam" }
```

#### `POST /student/wellbeing/settings`
Update wellbeing settings.

**Request Body:**
```json
{
  "opt_in": true,
  "mood_visibility": "teacher",  // "private" | "teacher" | "parent"
  "safe_language": true
}
```

#### `GET /student/wellbeing/history`
Get mood history.

**Query Params:** `from`, `to` (dates), `limit` (1-180, default: 30)

**Response (200):**
```json
{
  "entries": [
    {
      "date": "2026-02-10",
      "score": 4,
      "level": "happy",
      "tags": null,
      "notes": "Good day",
      "source": "mood_entry"
    }
  ]
}
```

---

### 4.16 AI Assistant

#### `POST /student/ai/chat`
Chat with AI tutor.

**Request Body:**
```json
{ "message": "Explain quadratic equations" }
```

#### `GET /student/ai/study-plan`
Get AI-generated study plan.

#### `GET /student/ai/recommendations`
Get AI learning recommendations.

#### `POST /student/ai/recommendations/{id}/feedback`
Provide feedback on recommendation.

#### `GET /student/ai/learning-path`
Get AI learning path.

---

### 4.17 Games

#### `GET /student/games/catalog`
Get available games.

#### `GET /student/games/wallet`
Get game wallet (keys/points).

#### `POST /student/games/{slug}/unlock`
Unlock a game.

#### `POST /student/games/{slug}/start`
Start a game session.

#### `POST /student/games/sessions/{sessionId}/end`
End a game session.

#### `GET /student/games/quran/questions`
Get Quran game questions.

#### `GET /student/games/quran/levels`
Get Quran game levels.

#### `POST /student/games/quran/progress`
Save Quran game progress.

---

### 4.18 Settings

#### `GET /student/settings`
Get student settings.

#### `PATCH /student/settings`
Update student settings.

#### `POST /student/change-password`
Change password.

#### `POST /student/send-password-reset`
Send password reset code.

#### `POST /student/verify-reset-code`
Verify reset code.

#### `POST /student/reset-password`
Reset password with code.

#### `GET /student/settings/notifications`
Get notification preferences.

#### `PATCH /student/settings/notifications`
Update notification preferences.

---

### 4.19 Streaks

#### `GET /student/streak/details`
Get streak details.

#### `POST /student/streak/activity`
Record daily activity.

#### `POST /student/streak/claim`
Claim streak reward.

#### `GET /student/streak/history`
Get streak history.

---

### 4.20 Goals

#### `GET /student/goals`
List all goals.

#### `GET /student/goals/active`
Get active goals.

#### `GET /student/goals/today`
Get today's goals.

#### `POST /student/goals`
Create a goal.

#### `PATCH /student/goals/{id}`
Update a goal.

#### `DELETE /student/goals/{id}`
Delete a goal.

#### `POST /student/goals/{id}/log`
Log goal progress.

#### `GET /student/goals/progress`
Get overall goals progress.

---

### 4.21 Achievements

#### `GET /student/achievements`
List achievements.

#### `GET /student/achievements/{id}`
Show achievement details.

#### `POST /student/achievements/{id}/share`
Share achievement.

#### `GET /student/achievements/pending`
Get pending achievements.

---

## 5. Parent Endpoints

**Prefix:** `/parent`
**Middleware:** `auth:sanctum`, `SetLanguage`, `parent.scope`

---

### 5.1 Dashboard

#### `GET /parent/dashboard`
Get parent dashboard stats (overview of all children).

---

### 5.2 Profile

#### `GET /parent/profile`
#### `PATCH /parent/profile`
#### `PATCH /parent/profile/password`

---

### 5.3 Children Management

#### `GET /parent/children/summary`
Summary of all children.

#### `GET /parent/children/{childId}`
Get child details. *(Note: under separate middleware group)*

#### `GET /parent/children/{childId}/dashboard`
Per-child dashboard.

#### `GET /parent/children/{childId}/teachers`
List child's teachers.

---

### 5.4 Academic Monitoring (per child)

#### `GET /parent/children/{childId}/assignments`
Child's assignments.

#### `GET /parent/children/{childId}/grades`
Child's grades.

#### `GET /parent/children/{childId}/skills`
Child's skills mastery.

#### `GET /parent/children/{childId}/outcomes`
Child's learning outcomes.

---

### 5.5 Progress Reports

#### `GET /parent/children/{childId}/progress/report`
Overall progress report.

#### `GET /parent/children/{childId}/progress/detailed`
Detailed progress.

#### `GET /parent/children/{childId}/progress/weekly`
Weekly progress.

#### `GET /parent/children/{childId}/progress/monthly`
Monthly progress.

#### `GET /parent/children/{childId}/progress/subject/{subjectId}`
Subject-specific progress.

---

### 5.6 Gamification

#### `GET /parent/children/{childId}/gamification`
Child gamification overview.

#### `GET /parent/children/{childId}/gamification/stats`
Gamification stats.

#### `GET /parent/children/{childId}/gamification/badges`
Earned badges.

#### `GET /parent/children/{childId}/gamification/achievements`
Achievements.

---

### 5.7 Attendance

#### `GET /parent/children/{childId}/attendance`
Attendance records.

#### `GET /parent/children/{childId}/attendance/monthly`
Monthly attendance.

#### `GET /parent/children/{childId}/attendance/summary`
Attendance summary.

---

### 5.8 Reading

#### `GET /parent/children/{childId}/reading`
Reading activity.

#### `GET /parent/children/{childId}/reading/recent`
Recent reading.

#### `GET /parent/children/{childId}/reading/goal`
Reading goal.

---

### 5.9 AI Insights

#### `GET /parent/children/{childId}/ai/study-plan`
AI study plan.

#### `GET /parent/children/{childId}/ai/recommendations`
AI recommendations.

---

### 5.10 Schedule

#### `GET /parent/children/{childId}/schedule`
Daily schedule.

#### `GET /parent/children/{childId}/schedule/weekly`
Weekly schedule.

---

### 5.11 Fees

#### `GET /parent/children/{childId}/fees`
Fee invoices.

#### `GET /parent/children/{childId}/fees/status`
Fee payment status.

---

### 5.12 Learning Gaps

#### `GET /parent/children/{childId}/learning-gaps`
Identified learning gaps.

#### `GET /parent/children/{childId}/recommendations`
Recommendations to address gaps.

---

### 5.13 Wellbeing

#### `GET /parent/wellbeing/summary/{childId}`
Child's wellbeing summary (limited view).

---

### 5.14 Notifications

#### `GET /parent/notifications`
#### `POST /parent/notifications/mark-all-read`
#### `PATCH /parent/notifications/{id}/read`
#### `DELETE /parent/notifications/{id}`

---

### 5.15 Contacts & Messaging

#### `GET /parent/contacts`
Get contacts.

#### `GET /parent/contacts/teachers`
Get child's teachers for messaging.

#### `POST /parent/messages/send`
Send message to teacher.

#### `GET /parent/messages`
List messages.

#### `GET /parent/messages/{id}`
Show message.

---

### 5.16 Announcements

#### `GET /parent/announcements`
School announcements.

---

### 5.17 Settings

#### `GET /parent/settings`
#### `PATCH /parent/settings`
#### `PATCH /parent/settings/notifications`

---

## 6. Teacher Endpoints

**Prefix:** `/teacher`
**Middleware:** `auth:sanctum`, `SetLanguage`, `TeacherLinkedScope`

---

### 6.1 Dashboard & Navigation

#### `GET /teacher/dashboard`
Teacher dashboard overview.

#### `GET /teacher/links`
Get teacher's linked classrooms, subjects, and groups.

#### `GET /teacher/contacts`
Get accessible contacts (students, parents).

---

### 6.2 Students

#### `GET /teacher/classrooms/{classroomId}/students`
List students in a classroom.

#### `GET /teacher/learning-groups/{groupId}/students`
List students in a learning group.

#### `GET /teacher/students/{studentId}`
Get student details.

#### `GET /teacher/students/{studentId}/portfolio`
Get student portfolio.

---

### 6.3 Assignments

#### `GET /teacher/assignments`
List teacher's assignments. Paginated.

#### `POST /teacher/assignments`
Create an assignment.

**Request Body:**
```json
{
  "title": "Chapter 5 Review",
  "description": "Review questions for Chapter 5",
  "subject_id": 3,
  "type": "homework",
  "due_date": "2026-02-20T23:59:59Z",
  "target_type": "classroom",     // "classroom" | "classrooms" | "student" | "students" | "learning_group" | "grade"
  "target_ids": [12],
  "total_points": 100,
  "questions": [
    {
      "question_text": "What is photosynthesis?",
      "type": "short_answer",
      "points": 20,
      "order": 1,
      "options": null
    }
  ],
  "skills": [5, 8],              // optional skill IDs
  "outcomes": [3]                 // optional outcome IDs
}
```

#### `GET /teacher/assignments/{id}`
Get assignment details.

#### `PATCH /teacher/assignments/{id}`
Update assignment (draft only).

#### `POST /teacher/assignments/{id}/publish`
Publish assignment (sends notifications to students).

#### `POST /teacher/assignments/{id}/close`
Close assignment.

#### `POST /teacher/assignments/{id}/duplicate`
Duplicate assignment.

---

### 6.4 Submissions & Grading

#### `GET /teacher/assignments/{assignmentId}/submissions`
List submissions for an assignment.

#### `GET /teacher/submissions/{submissionId}`
Get submission details.

#### `PATCH /teacher/submissions/{submissionId}/grade`
Grade a submission.

**Request Body:**
```json
{
  "score": 85,
  "feedback": "Good work! Pay attention to question 3.",
  "status": "graded"
}
```

---

### 6.5 AI Grading

#### `GET /teacher/submissions/{submissionId}/ai-grade`
Get AI-suggested grade.

#### `POST /teacher/submissions/{submissionId}/ai-grade`
Trigger AI grading.

#### `POST /teacher/submissions/{submissionId}/reset-ai-grade`
Reset AI grade.

#### `POST /teacher/ai-grading/bulk`
Bulk AI grading.

#### `GET /teacher/ai-grading/stats`
AI grading dashboard stats.

---

### 6.6 AI Assignment Tools (Rate-limited: AI tier)

#### `POST /teacher/ai/generate-questions`
Generate questions using AI.

#### `POST /teacher/ai/suggest-skills`
AI skill suggestions.

#### `POST /teacher/ai/analyze-content`
AI content analysis.

#### `GET /teacher/ai/tasks/{id}`
Get AI task status.

#### `GET /teacher/ai/lessons`
Get lessons for AI context.

#### `GET /teacher/ai/subjects/{subjectId}/skills`
Get subject skills for AI.

#### `POST /teacher/ai/generate/creativity`
Generate creative content.

#### `POST /teacher/ai/generate/project`
Generate project structure.

---

### 6.7 AI Content Generation (Rate-limited: AI tier)

#### `POST /teacher/ai/generate/lesson-plan`
#### `POST /teacher/ai/generate/worksheet`
#### `POST /teacher/ai/generate/presentation`

---

### 6.8 AI Chat Assistant

#### `GET /teacher/ai/conversations`
List AI chat conversations.

#### `POST /teacher/ai/conversations`
Create new AI chat.

#### `GET /teacher/ai/conversations/{id}`
Show AI conversation.

#### `POST /teacher/ai/conversations/{id}/messages`
Send message in AI chat.

#### `DELETE /teacher/ai/conversations/{id}`
Delete AI conversation.

---

### 6.9 Analytics

#### `GET /teacher/outcomes`
List learning outcomes.

#### `GET /teacher/analytics/skills/{classroomId}/{subjectId}`
Skills mastery analytics for classroom.

#### `GET /teacher/analytics/outcomes/{classroomId}/{subjectId}`
Outcomes mastery analytics.

---

### 6.10 Lesson Planning

#### `GET /teacher/library`
Search lesson library.

#### `GET /teacher/library/{id}`
Get library item details.

#### `GET /teacher/planning`
List lesson plans.

#### `POST /teacher/planning/generate`
Generate lesson plan via AI.

#### `POST /teacher/planning`
Save lesson plan.

#### `GET /teacher/planning/{id}`
Show lesson plan.

#### `DELETE /teacher/planning/{id}`
Delete lesson plan.

---

### 6.11 Worksheets

#### `GET /teacher/worksheets`
#### `POST /teacher/worksheets/generate` — AI generate
#### `POST /teacher/worksheets` — save
#### `GET /teacher/worksheets/{id}`
#### `DELETE /teacher/worksheets/{id}`

---

### 6.12 Presentations

#### `GET /teacher/presentations`
#### `POST /teacher/presentations/generate` — AI generate
#### `POST /teacher/presentations` — save
#### `GET /teacher/presentations/{id}`
#### `DELETE /teacher/presentations/{id}`

---

### 6.13 Remedial Plans

#### `POST /teacher/remedial/generate` — AI generate
#### `POST /teacher/remedial` — save
#### `GET /teacher/remedial` — list
#### `PUT /teacher/remedial/{id}` — update

---

### 6.14 Question Bank

#### `GET /teacher/question-bank`
List questions. Standard paginated resource.

#### `POST /teacher/question-bank`
Create question.

#### `GET /teacher/question-bank/{id}`
#### `PUT /teacher/question-bank/{id}`
#### `DELETE /teacher/question-bank/{id}`

#### `POST /teacher/question-bank/bulk`
Bulk create questions.

#### `GET /teacher/question-bank-stats`
Question bank statistics.

---

### 6.15 Settings

#### `GET /teacher/settings`
#### `PATCH /teacher/settings/profile`
#### `PATCH /teacher/settings/password`
#### `PATCH /teacher/settings/preferences`
#### `GET /teacher/audit-logs`

---

### 6.16 Progress & Analytics

#### `GET /teacher/classrooms/{classroomId}/progress`
Classroom progress report.

#### `GET /teacher/students/{studentId}/progress`
Individual student progress.

---

### 6.17 Notifications

#### `GET /teacher/notifications`
#### `POST /teacher/notifications/mark-all-read`
#### `PATCH /teacher/notifications/{id}/read`
#### `DELETE /teacher/notifications/{id}`

---

### 6.18 Wellbeing (Read-only)

#### `GET /teacher/wellbeing/alerts`
Student wellbeing alerts.

#### `GET /teacher/wellbeing/student/{id}/summary`
Individual student wellbeing summary.

---

### 6.19 Assessments

#### `GET /teacher/assessments/available`
Available assessments to assign.

#### `GET /teacher/assessments/my-assignments`
Teacher's assessment assignments.

#### `POST /teacher/assessments/assign`
Assign assessment to class/students.

#### `GET /teacher/assessments/assignments/{assignmentId}/results`
Get results for an assessment assignment.

#### `GET /teacher/assessments/attempts/{attemptId}`
View attempt details.

#### `PUT /teacher/assessments/results/{resultId}`
Update/override a result.

#### `GET /teacher/assessments/{id}/monitor`
Live proctoring/monitoring.

#### `GET /teacher/students/{id}/growth/{subjectId}`
Student growth per subject.

#### `GET /teacher/classrooms/{id}/growth/{subjectId}`
Classroom growth per subject.

#### `GET /teacher/learning-groups/{id}/growth/{subjectId}`
Learning group growth per subject.

---

### 6.20 Standardized Assessments

#### `GET /teacher/standardized`
List standardized assessments.

#### `POST /teacher/standardized/assign`
Assign standardized assessment.

#### `GET /teacher/standardized/assignments`
List standardized assignments.

#### `GET /teacher/standardized/results/{assessmentId}`
View standardized results.

---

## 7. Principal Endpoints

**Prefix:** `/principal`
**Middleware:** `auth:sanctum`, `SetLanguage`, `EnsureSchoolScope`, `EnsurePrincipalScope`

---

### 7.1 School Profile

#### `GET /principal/school`
Get school profile.

#### `PATCH /principal/school`
Update school profile.

#### `GET /principal/school/academic-years`
List academic years.

#### `POST /principal/school/academic-years`
Create academic year.

#### `GET /principal/school/academic-years/{yearId}/terms`
Get terms for an academic year.

#### Academic Terms CRUD: `GET|POST /principal/academic-terms`, `GET|PUT|DELETE /principal/academic-terms/{id}`

---

### 7.2 Analytics

#### `GET /principal/analytics`
School analytics.

#### `GET /principal/analytics/cohorts`
Cohort analytics.

#### `GET /principal/analytics/cohort/evolution`
Cohort evolution.

---

### 7.3 Users

#### Users CRUD: `GET|POST /principal/users`, `GET|PUT|DELETE /principal/users/{id}`
#### `POST /principal/users/{id}/toggle-status`
#### `POST /principal/users/{id}/reset-password`

---

### 7.4 Classrooms

#### `GET /principal/classrooms/grades`
Get available grade levels.

#### Classrooms CRUD: `GET|POST /principal/classrooms`, `GET|PUT|DELETE /principal/classrooms/{id}`

---

### 7.5 Subjects

#### `GET /principal/subjects/{id}/skills`
#### `GET /principal/subjects/{id}/groups`
#### Subjects CRUD: `GET|POST /principal/subjects`, `GET|PUT|DELETE /principal/subjects/{id}`

---

### 7.6 Student Profiles & Placement

#### `GET /principal/student-profiles`
#### `GET /principal/student-profiles/{id}`
#### `POST /principal/student-profiles/{id}`
#### `GET /principal/student-profiles/{id}/history`
#### `GET /principal/student-profiles/{id}/placements`
#### `POST /principal/student-profiles/{id}/placements`
#### `PATCH /principal/student-profiles/placements/{placement}`
#### `GET /principal/student-profiles/{id}/placements/history`

---

### 7.7 Student Assignment to Classes

#### `GET /principal/students/available`
Get students not assigned to any class.

#### `GET /principal/classrooms/{id}/students`
List students in a class.

#### `POST /principal/classrooms/{id}/students`
Add student to a class.

---

### 7.8 Teacher Assignments

#### `GET /principal/assignments/teachers`
List teacher assignments.

#### `POST /principal/assignments/teachers`
Create teacher-subject-classroom assignment.

#### `DELETE /principal/assignments/teachers/{id}`
Remove teacher assignment.

---

### 7.9 Parent-Student Linking

#### `GET /principal/linking/parents`
List parent-student links.

#### `POST /principal/linking/parents`
Link parent to student.

#### `DELETE /principal/linking/parents/{parentId}/student/{studentId}`
Unlink.

---

### 7.10 Reading Content

#### Reading CRUD: `GET|POST /principal/reading`, `GET|PUT|DELETE /principal/reading/{id}`
#### `POST /principal/reading/{id}/toggle-publish`
#### `POST /principal/reading/{materialId}/questions` — add question
#### `PUT /principal/reading/{materialId}/questions/{questionId}` — update question
#### `DELETE /principal/reading/{materialId}/questions/{questionId}` — delete question

---

### 7.11 Departments

#### Departments CRUD: `GET|POST /principal/departments`, `GET|PUT|DELETE /principal/departments/{id}`
#### `POST /principal/departments/{id}/assign-hod`
#### `POST /principal/departments/{id}/subjects`
#### `DELETE /principal/departments/{departmentId}/subjects/{subjectId}`
#### `GET /principal/hods/available`

---

### 7.12 Announcements

#### Announcements CRUD: `GET|POST /principal/announcements`, `GET|PUT|DELETE /principal/announcements/{id}`
#### `POST /principal/announcements/{id}/toggle-publish`

---

### 7.13 Bulk Import

#### `POST /principal/import/users`
Import users via Excel. Rate-limited (uploads tier).

#### `GET /principal/import/template`
Download sample import template.

---

### 7.14 Historical Data Import

#### `GET /principal/import/historical/template`
#### `GET /principal/import/historical/history`
#### `POST /principal/import/historical/preview`
#### `POST /principal/import/historical/confirm`
#### `DELETE /principal/import/historical/{batchId}` — rollback

---

### 7.15 Progress & Reports

#### `GET /principal/progress/dashboard`
#### `GET /principal/progress/students`
#### `GET /principal/progress/students/{id}/report`

---

### 7.16 Notifications

#### `GET /principal/notifications`
#### `POST /principal/notifications/mark-all-read`
#### `PATCH /principal/notifications/{id}/read`
#### `DELETE /principal/notifications/{id}`

---

### 7.17 Learning Groups

#### `GET /principal/learning-groups`

---

### 7.18 Audit Logs

#### `GET /principal/audit-logs`

---

## 8. HOD Endpoints

**Prefix:** `/hod`
**Middleware:** `auth:sanctum`, `EnsureHodScope`

---

### 8.1 Dashboard & Analytics

#### `GET /hod/dashboard`
Department dashboard.

#### `GET /hod/analytics/cohorts`
Cohort analytics.

#### `GET /hod/progress`
Department progress.

#### `GET /hod/compare/classes`
Compare classes performance.

#### `GET /hod/compare/teachers`
Compare teachers performance.

---

### 8.2 Reading Review

#### `GET /hod/reading/pending`
Pending reading materials for review.

#### `GET /hod/reading/{id}`
View reading material.

#### `POST /hod/reading/{id}/request-changes`
Request changes.

#### `POST /hod/reading/{id}/approve`
Approve material.

---

### 8.3 Action Notes

#### `GET /hod/action-notes`
List action notes.

#### `POST /hod/action-notes`
Create action note.

#### `PATCH /hod/action-notes/{id}/close`
Close action note.

---

### 8.4 Audit Logs

#### `GET /hod/audit-logs`

---

### 8.5 Assignments Oversight

#### `GET /hod/assignments`
List assignments in department subjects.

#### `GET /hod/assignments/{id}`
Show assignment details.

---

### 8.6 Progress

#### `GET /hod/progress`
Department progress.

#### `GET /hod/students/{id}/progress`
Individual student progress.

---

### 8.7 Reports

#### `GET /hod/reports/classes`
Get classes for report.

#### `GET /hod/reports/students`
Get students for report.

#### `GET /hod/reports/student`
Student report. **Query Params:** `student_id`, `subject_id`

#### `GET /hod/reports/classroom`
Classroom report. **Query Params:** `classroom_id`, `subject_id`

#### `GET /hod/reports/subject`
Subject report. **Query Params:** `subject_id`

---

## 9. Admin Endpoints

Admin endpoints are spread across multiple prefixes, all require `auth:sanctum`.

---

### 9.1 User Management

#### CRUD: `GET|POST /admin/users`, `GET|PUT|DELETE /admin/users/{id}`
#### `POST /admin/users/import` — bulk import
#### `POST /admin/users/{user}/reset-password`
#### `POST /admin/users/{id}/toggle-status`

---

### 9.2 Skills & Outcomes

#### Skills CRUD: `GET|POST /admin/skills`, `GET|PUT|DELETE /admin/skills/{id}`
#### `POST /admin/skills/assign` — assign skill to subject
#### `GET /admin/subjects/{subject}/skills`
#### `GET /admin/subjects`
#### Outcomes CRUD: `GET|POST /admin/outcomes`, `GET|PUT|DELETE /admin/outcomes/{id}`

---

### 9.3 Grade Levels

#### `GET /admin/grade-levels`
#### `POST /admin/grade-levels`
#### `PUT /admin/grade-levels/{id}`
#### `DELETE /admin/grade-levels/{id}`

---

### 9.4 Lessons (Central Library)

#### Lessons CRUD: `GET|POST /admin/lessons`, `GET|PUT|DELETE /admin/lessons/{id}`

---

### 9.5 Roles & Permissions

#### `GET /admin/permissions`
#### `POST /admin/roles`
#### `POST /admin/roles/{role}/permissions`
#### `DELETE /admin/roles/{role}`
#### `POST /admin/users/{user}/permissions`

---

### 9.6 Reading Materials

#### CRUD: `GET|POST /admin/reading-materials`, `GET|PUT|DELETE /admin/reading-materials/{id}`
#### `POST /admin/reading-materials/{material}/questions`
#### `POST /admin/reading-materials/{material}/toggle-publish`

---

### 9.7 Gamification Settings

#### `GET /admin/gamification/settings`
#### `POST /admin/gamification/settings`
#### `GET /admin/gamification/analytics`

---

### 9.8 Wellbeing Settings

#### `GET /admin/wellbeing/settings`
#### `POST /admin/wellbeing/settings`

---

### 9.9 Platform Settings

#### `GET /admin/platform-settings`
#### `GET /admin/platform-settings/{group}`
#### `PUT /admin/platform-settings`
#### `POST /admin/platform-settings/upload`
#### `POST /admin/platform-settings/clear-cache`

---

### 9.10 Translations

#### `GET /admin/translations`
#### `GET /admin/translations/{locale}`
#### `PUT /admin/translations/{locale}`
#### `POST /admin/translations/import`
#### `GET /admin/translations/export/{locale}`
#### `POST /admin/translations/copy`
#### `GET /admin/translations/missing`
#### `POST /admin/translations/clear-cache`

---

### 9.11 Locales

#### `GET /admin/locales`
#### `POST /admin/locales`
#### `GET /admin/locales/{locale}`
#### `PUT /admin/locales/{locale}`
#### `DELETE /admin/locales/{locale}`
#### `POST /admin/locales/{locale}/set-default`
#### `POST /admin/locales/{locale}/toggle-active`

---

### 9.12 AI Control Center

#### `GET /admin/ai/stats`
#### `GET /admin/ai/usage/daily`
#### `GET /admin/ai/usage/by-model`

#### Models CRUD:
- `GET /admin/ai/models`
- `POST /admin/ai/models`
- `PUT /admin/ai/models/{id}`
- `POST /admin/ai/models/{id}/toggle`
- `DELETE /admin/ai/models/{id}`

#### API Keys:
- `POST /admin/ai/models/{modelId}/keys`
- `DELETE /admin/ai/keys/{keyId}`
- `POST /admin/ai/keys/{keyId}/toggle`

#### AI Features:
- `GET /admin/ai/features`
- `POST /admin/ai/features`
- `PUT /admin/ai/features/{id}`
- `DELETE /admin/ai/features/{id}`

#### School AI Settings:
- `GET /admin/ai/schools`
- `GET /admin/ai/schools/{schoolId}`
- `PUT /admin/ai/schools/{schoolId}`
- `POST /admin/ai/schools/{schoolId}/toggle`

#### Prompts:
- `GET /admin/ai/prompts`
- `GET /admin/ai/prompts/{key}/history`
- `POST /admin/ai/prompts/{key}`

#### Usage Logs:
- `GET /admin/ai/logs`

#### Archive:
- `GET /admin/ai/archive`
- `GET /admin/ai/archive/filters`
- `GET /admin/ai/analytics`
- `GET /admin/ai/export`

---

### 9.13 Notification Management

#### `GET /admin/notifications`
#### `POST /admin/notifications/mark-all-read`
#### `PATCH /admin/notifications/{id}/read`
#### `DELETE /admin/notifications/{id}`

#### Rules:
- `GET /admin/notifications/rules`
- `POST /admin/notifications/rules`
- `PUT /admin/notifications/rules/{id}`
- `DELETE /admin/notifications/rules/{id}`
- `POST /admin/notifications/rules/{id}/toggle`

#### Templates:
- `GET /admin/notifications/templates`
- `POST /admin/notifications/templates`
- `PUT /admin/notifications/templates/{id}`
- `DELETE /admin/notifications/templates/{id}`

#### Broadcasting:
- `POST /admin/notifications/test`
- `POST /admin/notifications/broadcast`
- `GET /admin/notifications/history`
- `GET /admin/notifications/stats`

---

### 9.14 Communication & Moderation

#### `GET /admin/communication/settings`
#### `PUT /admin/communication/settings`
#### `POST /admin/communication/toggle`
#### `GET /admin/communication/roles`
#### `PUT /admin/communication/roles/{id}`
#### `POST /admin/communication/roles`
#### `GET /admin/communication/conversations`
#### `GET /admin/communication/conversations/{id}`
#### `POST /admin/communication/messages/{id}/moderate`
#### `POST /admin/communication/users/{userId}/block`
#### `GET /admin/communication/activity`
#### `GET /admin/communication/stats`
#### `POST /admin/communication/export`

---

### 9.15 Error Reports

#### `GET /admin/error-reports`
#### `GET /admin/error-reports/stats`
#### `GET /admin/error-reports/{id}`
#### `PUT /admin/error-reports/{id}/status`
#### `DELETE /admin/error-reports/{id}`

#### System Error Logs:
- `GET /errors`
- `GET /errors/{id}`

---

### 9.16 Subscription & Plans

#### Plans CRUD: `GET|POST /admin/plans`, `GET|PUT|DELETE /admin/plans/{id}`
#### `POST /admin/plans/compare`

#### Subscriptions:
- `GET /admin/subscriptions`
- `POST /admin/subscriptions`
- `POST /admin/subscriptions/{id}/upgrade`

#### Features:
- `GET /admin/features`
- `POST /admin/features`
- `PUT /admin/features/{id}`

---

### 9.17 Learning Groups

#### CRUD: `GET|POST /admin/learning-groups`, `GET|PATCH|DELETE /admin/learning-groups/{id}`
#### Members:
- `GET /admin/learning-groups/{id}/members`
- `POST /admin/learning-groups/{id}/members`
- `DELETE /admin/learning-groups/{id}/members/{memberId}`
#### `GET /admin/learning-groups/students/{studentId}/history`
#### `GET /admin/learning-groups/{id}/grades`

---

### 9.18 Student Profiles

#### `GET /admin/student-profiles`
#### `GET /admin/student-profiles/{studentId}`
#### `POST /admin/student-profiles/{studentId}`
#### `GET /admin/student-profiles/{studentId}/history`
#### Placements:
- `GET /admin/student-profiles/{studentId}/placements`
- `POST /admin/student-profiles/{studentId}/placements`
- `PATCH /admin/student-profiles/placements/{placement}`
- `GET /admin/student-profiles/{studentId}/placements/history`

---

### 9.19 Teaching Assignments

#### CRUD: `GET|POST /admin/teaching-assignments`, `GET|DELETE /admin/teaching-assignments/{id}`
#### `GET /admin/teaching-assignments/teachers/{teacherId}/assignments`
#### `GET /admin/teaching-assignments/targets/assignments`
#### `POST /admin/teaching-assignments/bulk-assign`

#### Teacher Capabilities:
- `GET /admin/teacher-capabilities`
- `POST /admin/teacher-capabilities`
- `GET /admin/teacher-capabilities/teachers/{teacherId}`

---

### 9.20 Assessments

#### CRUD: `GET|POST /admin/assessments`, `GET|PATCH /admin/assessments/{id}`
#### Questions:
- `POST /admin/assessments/{id}/questions`
- `PATCH /admin/assessments/questions/{questionId}`
- `DELETE /admin/assessments/questions/{questionId}`
#### `POST /admin/assessments/{id}/publish`
#### Passages:
- `GET /admin/assessments/{id}/passages`
- `POST /admin/assessments/{id}/passages`
- `DELETE /admin/assessments/passages/{passageId}`

---

### 9.21 Standardized Assessments

#### CRUD: `GET|POST /admin/standardized`, `GET|PATCH|DELETE /admin/standardized/{id}`
#### `POST /admin/standardized/{id}/questions`
#### `POST /admin/standardized/{id}/pilot`
#### `POST /admin/standardized/{id}/analyze`
#### `POST /admin/standardized/{id}/activate`
#### `POST /admin/standardized/{id}/stop`
#### `GET /admin/standardized/{id}/stats`
#### `POST /admin/standardized/{id}/passages`
#### `GET /admin/standardized-analytics`

---

### 9.22 Linking APIs

#### `POST /assign-teacher`
#### `POST /link-parent`

---

### 9.23 Audit Logs

#### `GET /admin/audit-logs`

---

### 9.24 School Feature Flags

#### `GET /schools/{school}/features`
#### `POST /schools/{school}/features`
#### `POST /schools/{school}/assign-principal`

---

## 10. Standard Response Patterns

### Pagination

All paginated endpoints return Laravel's standard pagination:

```json
{
  "data": [ ... ],
  "current_page": 1,
  "last_page": 5,
  "per_page": 20,
  "total": 95,
  "from": 1,
  "to": 20,
  "first_page_url": "...?page=1",
  "last_page_url": "...?page=5",
  "next_page_url": "...?page=2",
  "prev_page_url": null,
  "path": "https://api.bloomington.pro/api/..."
}
```

### Validation Errors (422)

```json
{
  "message": "The given data was invalid.",
  "errors": {
    "email": ["The email field is required."],
    "password": ["The password must be at least 8 characters."]
  }
}
```

### Not Found (404)

```json
{
  "message": "No query results for model [App\\Models\\Assignment] 999."
}
```

### Unauthorized (401)

```json
{
  "message": "Unauthenticated."
}
```

### Forbidden (403)

```json
{
  "message": "This action is unauthorized."
}
```

### Success Actions

```json
{ "message": "Resource created successfully" }
{ "status": "success" }
```

---

## Quick Reference: Complete Endpoint Count by Role

| Role | Approx. Endpoints |
|---|---|
| Public | 4 |
| Shared Auth | ~60 |
| Student | ~65 |
| Parent | ~40 |
| Teacher | ~75 |
| Principal | ~55 |
| HOD | ~20 |
| Admin | ~90 |
| **Total** | **~400+** |

---

**End of API Documentation**
