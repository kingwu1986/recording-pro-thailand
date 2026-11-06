// @ts-nocheck
import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { persistSession: false, autoRefreshToken: false } },
);

type Role = "teacher" | "student";
const STUDENT_LIMIT = 20;
const TEACHER_LIMIT = 5;

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" },
  });
}

function must(result: any): any {
  if (result.error) throw new Error(result.error.message);
  return result.data;
}

function related(value: any) {
  return Array.isArray(value) ? value[0] : value;
}

async function sha256(value: string) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((v) => v.toString(16).padStart(2, "0")).join("");
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map((v) => v.toString(16).padStart(2, "0")).join("");
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Bangkok",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(value));
}

async function getSettings() {
  return must(await supabase.from("app_settings").select("*").eq("id", 1).single());
}

function publicConfig(settings: Record<string, unknown>) {
  return {
    passScore: settings.pass_score,
    questionLimit: settings.question_limit,
    assignmentLimit: settings.assignment_limit,
    studentLimit: STUDENT_LIMIT,
    teacherLimit: TEACHER_LIMIT,
    speechLang: settings.speech_lang,
  };
}

async function verifyPassword(plain: string, passwordHash: string) {
  return must(await supabase.rpc("verify_password", {
    plain_text: plain,
    password_hash: passwordHash,
  })) === true;
}

async function hashPassword(plain: string) {
  return must(await supabase.rpc("hash_password", { plain_text: plain })) as string;
}

async function createSession(role: Role, teacherId: string, studentId: string | null = null) {
  const token = randomToken();
  const tokenHash = await sha256(token);
  await supabase.from("sessions").delete().lt("expires_at", new Date().toISOString());
  must(await supabase.from("sessions").insert({
    token_hash: tokenHash,
    role,
    teacher_id: teacherId,
    student_id: studentId,
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
  }));
  return token;
}

async function requireSession(token: string, role: Role) {
  if (!token) throw new Error("登录已过期，请重新登录。");
  const tokenHash = await sha256(token);
  const session = must(await supabase
    .from("sessions")
    .select("role,teacher_id,student_id,expires_at")
    .eq("token_hash", tokenHash)
    .eq("role", role)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle());
  if (!session) throw new Error("登录已过期，请重新登录。");
  return { ...session, tokenHash };
}

async function listPublicTeachers() {
  const rows = must(await supabase
    .from("teachers")
    .select("username,display_name")
    .eq("active", true)
    .order("display_name"));
  return rows.map((item: any) => ({ username: item.username, displayName: item.display_name }));
}

async function teacherData(teacherId: string) {
  const [teacherResult, setsResult, studentsResult, attemptsResult] = await Promise.all([
    supabase.from("teachers").select("id,username,display_name,is_admin").eq("id", teacherId).single(),
    supabase
      .from("question_sets")
      .select("id,version,title,assignment_date,published,created_at,questions(id,position,text)")
      .eq("teacher_id", teacherId)
      .order("assignment_date", { ascending: false })
      .order("created_at", { ascending: false }),
    supabase
      .from("students")
      .select("id,name,active,created_at")
      .eq("teacher_id", teacherId)
      .order("active", { ascending: false })
      .order("name")
      .limit(STUDENT_LIMIT),
    supabase
      .from("attempts")
      .select("id,created_at,score,grade,passed_count,question_count,student_id,set_id,students(name),question_sets(title,assignment_date,version)")
      .eq("teacher_id", teacherId)
      .order("created_at", { ascending: false })
      .limit(500),
  ]);

  const teacher = must(teacherResult);
  const sets = must(setsResult).map((set: any) => ({
    setId: set.id,
    setVersion: set.version,
    title: set.title,
    assignmentDate: set.assignment_date,
    published: set.published,
    createdAt: formatTime(set.created_at),
    questions: (set.questions || [])
      .sort((a: any, b: any) => a.position - b.position)
      .map((q: any) => ({ questionId: q.id, text: q.text })),
  }));
  const students = must(studentsResult).map((item: any) => ({
    studentId: item.id,
    name: item.name,
    active: item.active,
  }));
  const attempts = must(attemptsResult).map((item: any) => {
    const set = related(item.question_sets) || {};
    const student = related(item.students) || {};
    return {
      attemptId: item.id,
      timestamp: formatTime(item.created_at),
      setId: item.set_id,
      setVersion: set.version || "",
      assignmentTitle: set.title || "日期作业",
      assignmentDate: set.assignment_date || "",
      studentId: item.student_id,
      studentName: student.name || "已停用学生",
      score: item.score,
      grade: item.grade,
      passedCount: item.passed_count,
      questionCount: item.question_count,
      bestScore: item.score,
    };
  });
  const bestByStudent = new Map<string, number>();
  for (const item of attempts) {
    bestByStudent.set(item.studentId, Math.max(bestByStudent.get(item.studentId) || 0, item.score));
  }
  for (const item of attempts) item.bestScore = bestByStudent.get(item.studentId) || item.score;

  let teachers: any[] = [];
  if (teacher.is_admin) {
    teachers = must(await supabase
      .from("teachers")
      .select("id,username,display_name,active,is_admin")
      .order("created_at"))
      .map((item: any) => ({
        teacherId: item.id,
        username: item.username,
        displayName: item.display_name,
        active: item.active,
        isAdmin: item.is_admin,
      }));
  }

  const latestSet = sets[0] || null;
  return {
    teacher: {
      teacherId: teacher.id,
      username: teacher.username,
      displayName: teacher.display_name,
      isAdmin: teacher.is_admin,
    },
    sets,
    students,
    attempts,
    teachers,
    // 兼容尚未刷新到 v2 的 GitHub Pages 前端。
    questions: latestSet ? latestSet.questions : [],
    bestScores: students.map((student: any) => ({
      studentId: student.studentId,
      studentName: student.name,
      bestScore: bestByStudent.get(student.studentId) || 0,
    })),
    activeSet: latestSet ? {
      setId: latestSet.setId,
      setVersion: latestSet.setVersion,
      submittedAt: latestSet.createdAt,
      questionCount: latestSet.questions.length,
    } : { setId: "", setVersion: "", submittedAt: "", questionCount: 0 },
  };
}

// Export is separate from the limited, recent-results dashboard.
async function allTeacherGrades(teacherId: string) {
  const teacher = must(await supabase.from("teachers")
    .select("username,display_name").eq("id", teacherId).single());
  const students: any[] = [];
  const attempts: any[] = [];
  const pageSize = 500;
  for (let offset = 0; ; offset += pageSize) {
    const page = must(await supabase.from("students")
      .select("id,name,active").eq("teacher_id", teacherId)
      .order("id").range(offset, offset + pageSize - 1));
    students.push(...page.map((s: any) => ({ studentId: s.id, name: s.name, active: s.active })));
    if (page.length < pageSize) break;
  }
  const snapshotAt = new Date().toISOString();
  for (let offset = 0; ; offset += pageSize) {
    const page = must(await supabase.from("attempts")
      .select("id,student_id,set_id,created_at,score,grade,passed_count,question_count,question_sets(title,assignment_date)")
      .eq("teacher_id", teacherId).lte("created_at", snapshotAt)
      .order("created_at").order("id").range(offset, offset + pageSize - 1));
    attempts.push(...page.map((a: any) => {
      const set = related(a.question_sets) || {};
      return { attemptId: a.id, studentId: a.student_id, setId: a.set_id,
        timestamp: formatTime(a.created_at), score: a.score, grade: a.grade,
        passedCount: a.passed_count, questionCount: a.question_count,
        assignmentTitle: set.title || "日期作业", assignmentDate: set.assignment_date || "" };
    }));
    if (page.length < pageSize) break;
  }
  return { teacher: { username: teacher.username, displayName: teacher.display_name }, students, attempts };
}

async function studentDashboard(studentId: string, teacherId: string) {
  const [historyResult, setsResult] = await Promise.all([
    supabase
      .from("attempts")
      .select("created_at,score,grade,passed_count,question_count,set_id,question_sets(title,assignment_date,version)")
      .eq("student_id", studentId)
      .eq("teacher_id", teacherId)
      .order("created_at", { ascending: false })
      .limit(50),
    supabase
      .from("question_sets")
      .select("id,title,assignment_date,version,questions(id)")
      .eq("teacher_id", teacherId)
      .eq("published", true)
      .order("assignment_date", { ascending: false })
      .order("created_at", { ascending: false }),
  ]);
  const history = must(historyResult).map((item: any) => {
    const set = related(item.question_sets) || {};
    return {
      timestamp: formatTime(item.created_at),
      setId: item.set_id,
      setVersion: set.version || "",
      assignmentTitle: set.title || "日期作业",
      assignmentDate: set.assignment_date || "",
      score: item.score,
      grade: item.grade,
      passedCount: item.passed_count,
      questionCount: item.question_count,
    };
  });
  const completedIds = new Set(history.map((item: any) => item.setId));
  const availableAssignments = must(setsResult).map((item: any) => ({
    setId: item.id,
    setVersion: item.version,
    title: item.title,
    assignmentDate: item.assignment_date,
    questionCount: (item.questions || []).length,
    completed: completedIds.has(item.id),
  }));
  return {
    bestScore: history.reduce((best: number, item: any) => Math.max(best, item.score), 0),
    history,
    availableAssignments,
  };
}

function gradeFromScore(score: number) {
  if (score >= 100) return "A*";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  return "未通过";
}

async function route(fn: string, args: any[]) {
  if (fn === "listTeachers") return await listPublicTeachers();

  if (fn === "teacherLogin") {
    const legacyLogin = args.length < 2;
    const username = legacyLogin ? "teacher1" : String(args[0] || "").trim().toLowerCase();
    const password = String(legacyLogin ? args[0] : args[1] || "");
    const teacher = must(await supabase
      .from("teachers")
      .select("id,password_hash,active")
      .eq("username", username)
      .maybeSingle());
    if (!teacher || !teacher.active || !await verifyPassword(password, teacher.password_hash)) {
      throw new Error("教师账号或密码错误。");
    }
    const settings = await getSettings();
    const token = await createSession("teacher", teacher.id);
    return { token, config: publicConfig(settings), teacherData: await teacherData(teacher.id) };
  }

  if (fn === "studentLogin") {
    const legacyLogin = args.length < 3;
    const teacherUsername = legacyLogin ? "teacher1" : String(args[0] || "").trim().toLowerCase();
    const name = String(legacyLogin ? args[0] : args[1] || "").trim();
    const password = String(legacyLogin ? args[1] : args[2] || "");
    const teacher = must(await supabase
      .from("teachers")
      .select("id,display_name,active")
      .eq("username", teacherUsername)
      .maybeSingle());
    if (!teacher || !teacher.active) throw new Error("请选择正确的老师。");
    const student = must(await supabase
      .from("students")
      .select("id,name,password_hash,active")
      .eq("teacher_id", teacher.id)
      .eq("name", name)
      .maybeSingle());
    if (!student || !student.active || !await verifyPassword(password, student.password_hash)) {
      throw new Error("姓名或密码错误，或者账号已停用。");
    }
    const settings = await getSettings();
    const token = await createSession("student", teacher.id, student.id);
    return {
      token,
      config: publicConfig(settings),
      student: {
        studentId: student.id,
        name: student.name,
        teacherName: teacher.display_name,
        teacherUsername,
      },
      dashboard: await studentDashboard(student.id, teacher.id),
    };
  }

  if (fn === "getTeacherGrades") {
    const session = await requireSession(String(args[0] || ""), "teacher");
    return await allTeacherGrades(session.teacher_id);
  }

  if (fn === "getTeacherData") {
    const session = await requireSession(String(args[0] || ""), "teacher");
    return await teacherData(session.teacher_id);
  }

  if (fn === "getStudentDashboard") {
    const session = await requireSession(String(args[0] || ""), "student");
    return await studentDashboard(session.student_id, session.teacher_id);
  }

  if (fn === "saveQuestions") {
    const session = await requireSession(String(args[0] || ""), "teacher");
    const incoming = Array.isArray(args[1]) ? args[1] : [];
    const questions = incoming.map((item: any) => String(item?.text || "").trim()).filter(Boolean);
    const settings = await getSettings();
    if (!questions.length) throw new Error("请至少填写一道题。");
    if (questions.length > settings.question_limit) throw new Error(`每份作业最多 ${settings.question_limit} 道题。`);
    const assignmentDate = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Bangkok", year: "numeric", month: "2-digit", day: "2-digit",
    }).format(new Date());
    const created = must(await supabase.from("question_sets").insert({
      teacher_id: session.teacher_id,
      title: `${assignmentDate} 复述作业`,
      assignment_date: assignmentDate,
      published: true,
    }).select("id").single());
    must(await supabase.from("questions").insert(questions.map((text: string, index: number) => ({
      set_id: created.id,
      position: index + 1,
      text,
    }))));
    return await teacherData(session.teacher_id);
  }

  if (fn === "saveStudents") {
    const session = await requireSession(String(args[0] || ""), "teacher");
    const incoming = Array.isArray(args[1]) ? args[1] : [];
    if (incoming.filter((item: any) => String(item?.name || "").trim()).length > STUDENT_LIMIT) {
      throw new Error(`每位老师最多 ${STUDENT_LIMIT} 名学生。`);
    }
    const seenIds: string[] = [];
    for (const raw of incoming) {
      const name = String(raw?.name || "").trim();
      if (!name) continue;
      const studentId = String(raw?.studentId || "");
      const password = String(raw?.password || "");
      if (studentId) {
        const changes: Record<string, unknown> = {
          name,
          active: raw.active !== false,
          updated_at: new Date().toISOString(),
        };
        if (password) changes.password_hash = await hashPassword(password);
        must(await supabase.from("students").update(changes)
          .eq("id", studentId).eq("teacher_id", session.teacher_id));
        seenIds.push(studentId);
      } else {
        if (password.length < 4) throw new Error(`请为学生“${name}”设置至少4位密码。`);
        const created = must(await supabase.from("students").insert({
          teacher_id: session.teacher_id,
          name,
          password_hash: await hashPassword(password),
          active: raw.active !== false,
        }).select("id").single());
        seenIds.push(created.id);
      }
    }
    const existing = must(await supabase.from("students").select("id").eq("teacher_id", session.teacher_id));
    const removedIds = existing.map((item: any) => item.id).filter((id: string) => !seenIds.includes(id));
    if (removedIds.length) {
      must(await supabase.from("students").update({ active: false })
        .eq("teacher_id", session.teacher_id).in("id", removedIds));
    }
    return await teacherData(session.teacher_id);
  }

  if (fn === "saveDateAssignment") {
    const session = await requireSession(String(args[0] || ""), "teacher");
    const raw = args[1] || {};
    const setId = String(raw.setId || "");
    const title = String(raw.title || "").trim();
    const assignmentDate = String(raw.assignmentDate || "").trim();
    const published = raw.published !== false;
    const questions = (Array.isArray(raw.questions) ? raw.questions : [])
      .map((q: any) => String(q?.text || "").trim())
      .filter(Boolean);
    const settings = await getSettings();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(assignmentDate)) throw new Error("请选择作业日期。");
    if (!title) throw new Error("请填写作业名称。");
    if (!questions.length) throw new Error("请至少填写一道题。");
    if (questions.length > settings.question_limit) throw new Error(`每份作业最多 ${settings.question_limit} 道题。`);

    let targetId = setId;
    let wasPublished = false;
    if (setId) {
      const existing = must(await supabase
        .from("question_sets")
        .select("id,published")
        .eq("id", setId)
        .eq("teacher_id", session.teacher_id)
        .maybeSingle());
      if (!existing) throw new Error("这份作业不存在或不属于当前老师。");
      wasPublished = existing.published === true;
      must(await supabase.from("question_sets").update({
        title,
        assignment_date: assignmentDate,
        published,
      }).eq("id", setId).eq("teacher_id", session.teacher_id));
      must(await supabase.from("questions").delete().eq("set_id", setId));
    } else {
      const created = must(await supabase.from("question_sets").insert({
        teacher_id: session.teacher_id,
        title,
        assignment_date: assignmentDate,
        published,
      }).select("id").single());
      targetId = created.id;
    }
    must(await supabase.from("questions").insert(questions.map((text: string, index: number) => ({
      set_id: targetId,
      position: index + 1,
      text,
    }))));

    // Enqueue exactly once when a recording assignment is first published.
    // The mail worker resolves recipients from the primary classroom database.
    if (published && !wasPublished) {
      const teacher = must(await supabase
        .from("teachers")
        .select("username,display_name")
        .eq("id", session.teacher_id)
        .single());
      must(await supabase.from("homework_email_outbox").upsert({
        source_app: "recording",
        external_assignment_id: targetId,
        teacher_username: teacher.username,
        teacher_display_name: teacher.display_name,
        title,
        assignment_date: assignmentDate,
        status: "pending",
        error_message: null,
        sent_at: null,
      }, {
        onConflict: "source_app,external_assignment_id",
        ignoreDuplicates: true,
      }));
    }
    return await teacherData(session.teacher_id);
  }

  if (fn === "upsertStudent") {
    const session = await requireSession(String(args[0] || ""), "teacher");
    const raw = args[1] || {};
    const studentId = String(raw.studentId || "");
    const name = String(raw.name || "").trim();
    const password = String(raw.password || "");
    if (!name) throw new Error("请填写学生姓名。");
    if (studentId) {
      const changes: Record<string, unknown> = {
        name,
        active: raw.active !== false,
        updated_at: new Date().toISOString(),
      };
      if (password) changes.password_hash = await hashPassword(password);
      const updated = must(await supabase.from("students").update(changes)
        .eq("id", studentId)
        .eq("teacher_id", session.teacher_id)
        .select("id")
        .maybeSingle());
      if (!updated) throw new Error("学生不存在或不属于当前老师。");
    } else {
      if (password.length < 4) throw new Error("新学生密码至少需要 4 个字符。");
      const countResult = await supabase
        .from("students")
        .select("id", { count: "exact", head: true })
        .eq("teacher_id", session.teacher_id);
      if (countResult.error) throw new Error(countResult.error.message);
      if ((countResult.count || 0) >= STUDENT_LIMIT) throw new Error(`每位老师最多 ${STUDENT_LIMIT} 名学生。`);
      must(await supabase.from("students").insert({
        teacher_id: session.teacher_id,
        name,
        password_hash: await hashPassword(password),
        active: raw.active !== false,
      }));
    }
    return await teacherData(session.teacher_id);
  }

  if (fn === "deactivateStudent") {
    const session = await requireSession(String(args[0] || ""), "teacher");
    const studentId = String(args[1] || "");
    must(await supabase.from("students").update({
      active: false,
      updated_at: new Date().toISOString(),
    }).eq("id", studentId).eq("teacher_id", session.teacher_id));
    return await teacherData(session.teacher_id);
  }

  if (fn === "saveTeacherAccount") {
    const session = await requireSession(String(args[0] || ""), "teacher");
    const current = must(await supabase
      .from("teachers")
      .select("is_admin")
      .eq("id", session.teacher_id)
      .single());
    if (!current.is_admin) throw new Error("只有管理员可以新增教师账号。");
    const teacherCount = await supabase.from("teachers").select("id", { count: "exact", head: true });
    if (teacherCount.error) throw new Error(teacherCount.error.message);
    if ((teacherCount.count || 0) >= TEACHER_LIMIT) throw new Error(`最多只能创建 ${TEACHER_LIMIT} 个教师账号。`);
    const raw = args[1] || {};
    const username = String(raw.username || "").trim().toLowerCase();
    const displayName = String(raw.displayName || "").trim();
    const password = String(raw.password || "");
    if (!/^[a-z0-9_-]{3,40}$/.test(username)) throw new Error("教师账号只能使用3至40位字母、数字、下划线或横线。");
    if (!displayName) throw new Error("请填写教师姓名。");
    if (password.length < 8) throw new Error("教师密码至少需要8个字符。");
    must(await supabase.from("teachers").insert({
      username,
      display_name: displayName,
      password_hash: await hashPassword(password),
      active: true,
      is_admin: false,
    }));
    return await teacherData(session.teacher_id);
  }

  if (fn === "changeTeacherPassword") {
    const session = await requireSession(String(args[0] || ""), "teacher");
    const oldPassword = String(args[1] || "");
    const newPassword = String(args[2] || "");
    if (newPassword.length < 8) throw new Error("新密码至少需要8个字符。");
    const teacher = must(await supabase
      .from("teachers")
      .select("password_hash")
      .eq("id", session.teacher_id)
      .single());
    if (!await verifyPassword(oldPassword, teacher.password_hash)) throw new Error("旧密码错误。");
    must(await supabase.from("teachers").update({
      password_hash: await hashPassword(newPassword),
      updated_at: new Date().toISOString(),
    }).eq("id", session.teacher_id));
    return { success: true };
  }

  if (fn === "startAssignment") {
    const session = await requireSession(String(args[0] || ""), "student");
    let setId = String(args[1] || "");
    if (!setId) {
      const latest = must(await supabase.from("question_sets").select("id")
        .eq("teacher_id", session.teacher_id).eq("published", true)
        .order("assignment_date", { ascending: false }).order("created_at", { ascending: false })
        .limit(1).maybeSingle());
      setId = latest?.id || "";
    }
    const set = must(await supabase
      .from("question_sets")
      .select("id,version,title,assignment_date,published")
      .eq("id", setId)
      .eq("teacher_id", session.teacher_id)
      .eq("published", true)
      .maybeSingle());
    if (!set) throw new Error("这份日期作业不存在或尚未发布。");
    const questions = must(await supabase
      .from("questions")
      .select("id,position,text")
      .eq("set_id", set.id)
      .order("position"));
    if (!questions.length) throw new Error("这份作业还没有题目。");
    const assignment = must(await supabase.from("assignments").insert({
      teacher_id: session.teacher_id,
      student_id: session.student_id,
      set_id: set.id,
      question_ids: questions.map((q: any) => q.id),
    }).select("id").single());
    const settings = await getSettings();
    return {
      assignmentId: assignment.id,
      setId: set.id,
      setVersion: set.version,
      title: set.title,
      assignmentDate: set.assignment_date,
      passScore: settings.pass_score,
      questions: questions.map((q: any) => ({ questionId: q.id, text: q.text })),
    };
  }

  if (fn === "saveAttempt") {
    const session = await requireSession(String(args[0] || ""), "student");
    const assignmentId = String(args[1] || "");
    const results = Array.isArray(args[2]) ? args[2] : [];
    const assignment = must(await supabase
      .from("assignments")
      .select("id,teacher_id,student_id,set_id,question_ids,submitted_at")
      .eq("id", assignmentId)
      .eq("teacher_id", session.teacher_id)
      .eq("student_id", session.student_id)
      .maybeSingle());
    if (!assignment || assignment.submitted_at) throw new Error("这份作业不存在或已经提交。");
    const expectedIds = assignment.question_ids as string[];
    if (results.length !== expectedIds.length) throw new Error("作业题目不完整，请重新开始。");
    for (const result of results) {
      if (!expectedIds.includes(String(result?.questionId || ""))) throw new Error("作业题目不匹配。");
      if (!Number.isFinite(Number(result?.score)) || Number(result.score) < 0 || Number(result.score) > 100) {
        throw new Error("成绩数据无效。");
      }
    }
    const score = Math.round(results.reduce((sum: number, item: any) => sum + Number(item.score), 0) / results.length);
    const settings = await getSettings();
    const passedCount = results.filter((item: any) => Number(item.score) >= settings.pass_score).length;
    const grade = gradeFromScore(score);
    must(await supabase.from("attempts").insert({
      assignment_id: assignment.id,
      teacher_id: session.teacher_id,
      student_id: session.student_id,
      set_id: assignment.set_id,
      score,
      grade,
      passed_count: passedCount,
      question_count: results.length,
      results,
    }));
    must(await supabase.from("assignments").update({
      submitted_at: new Date().toISOString(),
    }).eq("id", assignment.id));
    return {
      score,
      grade,
      dashboard: await studentDashboard(session.student_id, session.teacher_id),
    };
  }

  if (fn === "logout") {
    const token = String(args[0] || "");
    if (token) must(await supabase.from("sessions").delete().eq("token_hash", await sha256(token)));
    return { success: true };
  }

  throw new Error("未知接口。");
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method === "GET") {
    const sourceUrl = `${Deno.env.get("SUPABASE_URL")}/storage/v1/object/public/recording-pro/index.html`;
    const source = await fetch(sourceUrl);
    if (!source.ok) return new Response("Recording Pro 页面尚未上传。", { status: 503 });
    return new Response(await source.text(), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-cache",
        "Content-Security-Policy": "default-src 'self'; connect-src 'self' https://*.supabase.co; img-src 'self' data:; media-src 'self' blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
      },
    });
  }
  if (request.method !== "POST") return json({ ok: false, error: "Method not allowed" }, 405);
  try {
    const body = await request.json();
    const value = await route(String(body?.fn || ""), Array.isArray(body?.args) ? body.args : []);
    return json({ ok: true, value });
  } catch (error) {
    console.error(error);
    const message = error instanceof Error ? error.message : String(error);
    const status = /密码|登录|账号|不属于|只有管理员/.test(message) ? 401 : 400;
    return json({ ok: false, error: message }, status);
  }
});

