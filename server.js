import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import * as cheerio from 'cheerio';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import { EOL } from 'os';

dotenv.config();
const app = express();

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
const API_KEY = process.env.API_KEY;
const CSE_ID = process.env.CSE_ID;

if (!JWT_SECRET) { console.error("FATAL ERROR: JWT_SECRET is not defined in .env file."); process.exit(1); }
if (!MONGODB_URI) { console.error("FATAL ERROR: MONGODB_URI is not defined in .env file."); process.exit(1); }

app.use(cors());
app.use(express.json());

mongoose.connect(MONGODB_URI)
.then(() => console.log('Successfully connected to MongoDB'))
.catch(err => { console.error('MongoDB connection error:', err); process.exit(1); });

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3 },
  email: { type: String, trim: true, lowercase: true, unique: true, sparse: true, match: [/\S+@\S+\.\S+/, 'is invalid'] },
  passwordHash: { type: String, required: true }
}, { timestamps: true });
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
const User = mongoose.model('User', userSchema);

const interactionHistorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  question: { type: String, required: true },
  answer: { type: String, required: true },
  source: { type: String },
  timestamp: { type: Date, default: Date.now },
});
interactionHistorySchema.index({ userId: 1, timestamp: -1 });
const InteractionHistory = mongoose.model('InteractionHistory', interactionHistorySchema);

const stopWords = new Set([
  'a', 'an', 'and', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
  'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'should', 'can',
  'could', 'may', 'might', 'must', 'i', 'you', 'he', 'she', 'it', 'we', 'they',
  'me', 'him', 'her', 'us', 'them', 'my', 'your', 'his', 'its', 'our', 'their',
  'of', 'at', 'by', 'for', 'with', 'about', 'to', 'from', 'in', 'out', 'on', 'off',
  'what', 'who', 'when', 'where', 'why', 'how', 'tell', 'me', 'please', 'explain',
  'describe', 'whats', 'whos', 'what is', 'who is', 'can you tell me', 'of india', 'in india'
]);

const indiaRelatedKeywords = [
  'india', 'indian', 'bharat', 'hindustan', 'delhi', 'mumbai', 'kolkata', 'chennai',
  'bengaluru', 'hyderabad', 'pune', 'ahmedabad', 'jaipur', 'lucknow', 'ganges',
  'yamuna', 'himalayas', 'taj mahal', 'modi', 'gandhi', 'nehru', 'bollywood',
  'cricket', 'rupee', 'isro', 'vedas', 'upanishads', 'mahabharata', 'ramayana',
  'mughal', 'gupta', 'maurya', 'independence', 'constitution', 'parliament',
  'state', 'states of india', 'festival', 'culture', 'history of india', 'geography of india',
  'sachin tendulkar', 'virat kohli', 'batsman', 'prime minister', 'uttar pradesh', 'maharashtra',
  'karnataka', 'tamil nadu', 'rajasthan', 'ancient india', 'freedom struggle', 'master',
  'rana pratap', 'maharana pratap', 'president'
];

function normalizeTextForSearch(text) {
  if (typeof text !== 'string') return '';
  return text.toLowerCase().replace(/[?.!,';:]/g, '').trim().replace(/\s+/g, ' ');
}

function getSignificantTokens(text) {
  if (typeof text !== 'string') return [];
  return normalizeTextForSearch(text)
    .split(/\s+/)
    .filter(token => token.length > 1 && !stopWords.has(token));
}

function isQueryIndiaRelated(query) {
  const normalizedQuery = normalizeTextForSearch(query);
  if (indiaRelatedKeywords.some(keyword => normalizedQuery.includes(keyword.toLowerCase()))) {
    return true;
  }
  const significantQueryTokens = getSignificantTokens(query);
  return significantQueryTokens.some(token => indiaRelatedKeywords.includes(token));
}

const bharatBotKnowledgeBase_unused = {};

let bharatAIKnowledgeBase = {
  "tell me about india's independence movement": "India's independence movement was a long and multifaceted struggle against British colonial rule, spanning several decades. Key figures like Mahatma Gandhi, Jawaharlal Nehru, Sardar Patel, Subhas Chandra Bose, and many others led various forms of protests, including non-violent civil disobedience, armed resistance, and political negotiations. Major events include the Non-Cooperation Movement, Civil Disobedience Movement (including the Dandi March), Quit India Movement, and the activities of revolutionary groups. The movement culminated in India gaining independence on August 15, 1947, but also led to the partition of the country into India and Pakistan.",
 "who was mahatma gandhi": "Mohandas Karamchand Gandhi, respectfully known as Mahatma Gandhi, was an Indian lawyer, anti-colonial nationalist, and political ethicist. He employed nonviolent resistance (Satyagraha) to lead the successful campaign for India's independence from British rule and, in turn, inspired movements for civil rights and freedom across the world. He is revered in India as the 'Father of the Nation'.",
 "what was the quit india movement": "The Quit India Movement (Bharat Chhodo Andolan) was a movement launched at the Bombay session of the All India Congress Committee by Mahatma Gandhi on August 8, 1942, during World War II, demanding an end to British rule in India. Gandhi made a call to 'Do or Die' in his Quit India speech delivered in Bombay. The movement involved mass protests, strikes, and acts of civil disobedience across the country.",
"describe indian classical music": "Indian classical music is a rich and ancient tradition categorized into two main subgenres: Hindustani music from North India and Carnatic music from South India. Both systems are based on the concepts of 'raga' (melodic framework) and 'tala' (rhythmic cycle). It's characterized by improvisation, intricate melodic patterns, and a deep spiritual and emotional connection. Instruments commonly used include the sitar, tabla, veena, mridangam, flute (bansuri), and sarod.",
"what are some famous indian dances": "India has a vast array of classical and folk dance forms. Some famous classical dances include Bharatanatyam (Tamil Nadu), Kathak (North India), Kathakali (Kerala), Kuchipudi (Andhra Pradesh), Odissi (Odisha), Manipuri (Manipur), Mohiniyattam (Kerala), and Sattriya (Assam). Folk dances vary greatly by region and include Bhangra and Giddha (Punjab), Garba and Dandiya Raas (Gujarat), Bihu (Assam), Lavani (Maharashtra), and many more.",
"explain the concept of dharma in indian philosophy": "Dharma is a key concept with multiple meanings in Indian religions—Hinduism, Buddhism, Jainism, and Sikhism. It generally refers to one's righteous duty, moral law, cosmic order, principles of conduct, or the path of righteousness. Following one's dharma is believed to lead to personal and societal well-being and spiritual progress. The specific understanding of dharma can vary depending on an individual's social standing, stage of life, and the philosophical school.",
"major geographical features of india": "India boasts diverse geographical features. In the north, it has the Himalayan mountain range, the highest in the world. South of the Himalayas lies the fertile Indo-Gangetic Plain. The western part has the Thar Desert. The southern part is a peninsula, featuring the Deccan Plateau, bordered by the Western Ghats and Eastern Ghats (coastal mountain ranges), and a long coastline along the Arabian Sea, Indian Ocean, and Bay of Bengal. India also has numerous rivers, islands like the Andaman and Nicobar, and Lakshadweep.",
"what is the deccan plateau": "The Deccan Plateau is a large plateau in western and southern India. It rises to 100 metres (330 ft) in the north, and to more than 1,000 metres (3,300 ft) in the south, forming a raised triangle within the south-pointing triangle of the Indian coastline. It is bordered by the Western Ghats and Eastern Ghats and covers a significant portion of the Indian peninsula, spanning across several states.",
"overview of indian economy": "The Indian economy is a developing mixed economy. It is the world's fifth-largest economy by nominal GDP and the third-largest by purchasing power parity (PPP). Key sectors include services (which contribute the most to GDP), agriculture (a major employer), and industry. India has seen significant economic growth in recent decades, driven by reforms, a large young population, and a growing middle class. Challenges include poverty, infrastructure development, and job creation.",
 "what is make in india": "Make in India is a major national initiative launched by the Government of India in 2014 designed to facilitate investment, foster innovation, enhance skill development, protect intellectual property, and build best-in-class manufacturing infrastructure in the country. The primary objective of this initiative is to attract investments from across the globe and strengthen India's manufacturing sector.",
"tell me about isro's achievements": "The Indian Space Research Organisation (ISRO) has numerous significant achievements. These include the successful Chandrayaan missions to the Moon (including landing near the lunar south pole with Chandrayaan-3), the Mangalyaan Mars Orbiter Mission, developing indigenous satellite launch vehicles like the PSLV and GSLV, launching a multitude of communication, navigation, and Earth observation satellites, and setting records for launching multiple satellites in a single mission. ISRO is also working on a human spaceflight program called Gaganyaan.",
"what can you tell me about india": "India is a vast and incredibly diverse country in South Asia, known for its rich history spanning millennia, vibrant cultures, myriad languages, varied geography from snow-capped Himalayas to tropical beaches, and a rapidly growing economy. It's the world's most populous democracy. From ancient civilizations like the Indus Valley Civilization to the Mughal Empire and British colonial rule, its history is complex and fascinating. Culturally, it's a melting pot of religions, traditions, festivals, art forms, and cuisines that vary significantly from region to region. What specific aspect of India are you interested in learning more about? Perhaps its history, culture, geography, or current affairs?",
 "what is your purpose as bharat ai": "As Bharat AI, my purpose is to provide you with comprehensive and detailed information about India. I'm here to help you explore its history, culture, geography, achievements, and more, drawing from my extensive internal knowledge base. Ask me anything you'd like to know about India!",
"Hi": "Hello, I am BharatBot AI. What do you want to ask?"
};

function searchBharatAIKB(query) {
  const normalizedQuery = normalizeTextForSearch(query);
  const querySignificantTokens = getSignificantTokens(query);

  if (bharatAIKnowledgeBase[normalizedQuery]) {
    return bharatAIKnowledgeBase[normalizedQuery];
  }
  if (querySignificantTokens.length === 0 && bharatAIKnowledgeBase[normalizedQuery]) {
     return bharatAIKnowledgeBase[normalizedQuery];
  }
  if (querySignificantTokens.length === 0) return null;

  let bestMatch = null;
  let highestScore = -1; 

  for (const key in bharatAIKnowledgeBase) {
    const normalizedKey = normalizeTextForSearch(key);
    const keySignificantTokens = getSignificantTokens(key);
    if (keySignificantTokens.length === 0) continue;

    let currentScore = 0;
    let matchedKeywords = 0;

    const significantQueryPhrase = querySignificantTokens.join(' ');
    if (significantQueryPhrase.length > 3 && normalizedKey.includes(significantQueryPhrase)) {
        currentScore += 30; 
    }

    querySignificantTokens.forEach(qToken => {
      if (normalizedKey.includes(qToken)) { 
        currentScore += 7; 
        matchedKeywords++; 
      }
      if (keySignificantTokens.includes(qToken)){ 
        currentScore += 5; 
      }
    });

    if (matchedKeywords > 0) { 
      currentScore += matchedKeywords * 4; 
    }

    if (querySignificantTokens.length > 0) {
        const matchRatio = matchedKeywords / querySignificantTokens.length;
        if (matchRatio > 0.7) currentScore += 15; 
        if (matchRatio === 1 && querySignificantTokens.length === keySignificantTokens.length && querySignificantTokens.every((val, index) => val === keySignificantTokens[index])) {
             currentScore += 50; 
        }
    }
    
    const lengthDifferencePenalty = Math.abs(keySignificantTokens.length - querySignificantTokens.length);
    currentScore -= lengthDifferencePenalty * 1; 

    if (currentScore > highestScore) {
      highestScore = currentScore;
      bestMatch = bharatAIKnowledgeBase[key];
    }
  }
  
  if (highestScore > 18) { 
      return bestMatch;
  }
  return null;
}

async function searchAndScrapeInternet(question) {
  if (!API_KEY || !CSE_ID) {
    console.warn("Google Search API_KEY or CSE_ID not configured. Internet search is disabled.");
    return { error: "External search service is not configured.", source: "Configuration Error" };
  }
  const url = `https://www.googleapis.com/customsearch/v1?key=${API_KEY}&cx=${CSE_ID}&q=${encodeURIComponent(question)}`;
  try {
    const searchResponse = await fetch(url);
    if (!searchResponse.ok) {
      const errorText = await searchResponse.text();
      console.error(`Google API error: ${searchResponse.status} ${searchResponse.statusText}`, errorText);
      return { error: `Failed to fetch from Google Search (Status: ${searchResponse.status})`, source: "Google API Error" };
    }
    const searchData = await searchResponse.json();
    if (searchData.error) {
        console.error("Google API returned an error object:", searchData.error);
        return { error: searchData.error.message || "Google Search API returned an error.", source: "Google API Response Error" };
    }
    if (searchData.items && searchData.items.length > 0) {
      const articleUrl = searchData.items[0].link;
      const articleTitle = searchData.items[0].title;
      try {
        const pageResponse = await fetch(articleUrl, { headers: { 'User-Agent': 'BharatBot/1.0' } });
        if (!pageResponse.ok) {
          return { result: `Found link: ${articleUrl} (${articleTitle}). Could not fetch full content (Status: ${pageResponse.status})`, source: 'Google Search (Link Only)', sourceUrl: articleUrl, sourceTitle: articleTitle };
        }
        const html = await pageResponse.text();
        const $ = cheerio.load(html);
        let fullText = '';
        $('article p, .article-body p, .post-content p, .entry-content p, .td-post-content p, div[itemprop="articleBody"] p').each((i, el) => {
          const text = $(el).text().trim();
          if (text.length > 70) fullText += text + EOL + EOL;
        });
        if (!fullText) {
          $('.content p, main p, div[role="main"] p, .story-content p').each((i, el) => {
            const text = $(el).text().trim();
            if (text.length > 70) fullText += text + EOL + EOL;
          });
        }
        if (!fullText) {
          $('p').each((i, el) => {
            const text = $(el).text().trim();
            if (text.length > 70) fullText += text + EOL + EOL;
          });
        }
        return { result: fullText.trim() || "Content found, but no suitable paragraphs extracted.", source: 'Google Search (Scraped)', sourceUrl: articleUrl, sourceTitle: articleTitle };
      } catch (scrapeError) {
        console.error("Error scraping article:", scrapeError);
        return { result: `Found link: ${articleUrl} (${articleTitle}). Error extracting content.`, source: 'Google Search (Scrape Error)', sourceUrl: articleUrl, sourceTitle: articleTitle };
      }
    } else {
      return { result: "No relevant information found on the internet for that query.", source: 'Google Search (No Results)' };
    }
  } catch (apiError) {
    console.error("Error with Google Search API call:", apiError);
    return { error: "Error during internet search.", source: "Google API Call Error" };
  }
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ error: "No token provided" });
    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) {
            console.error("JWT Verification Error:", err.message);
            return res.status(403).json({ error: "Invalid or expired token" });
        }
        req.user = userPayload;
        next();
    });
};

app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password are required" });
  if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters long" });
  try {
    const existingUser = await User.findOne({ username: username.toLowerCase() });
    if (existingUser) return res.status(409).json({ error: "Username already taken" });
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const newUser = new User({ username: username.toLowerCase(), passwordHash });
    const savedUser = await newUser.save();
    const token = jwt.sign({ userId: savedUser._id, username: savedUser.username }, JWT_SECRET, { expiresIn: '200h' });
    res.status(201).json({ message: "User registered successfully", token, user: { id: savedUser._id, username: savedUser.username } });
  } catch (error) {
    console.error("Error during registration:", error);
    if (error.code === 11000) return res.status(409).json({ error: "Username already taken (database)." });
    res.status(500).json({ error: "Server error during registration" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password are required" });
  try {
    const user = await User.findOne({ username: username.toLowerCase() });
    if (!user) return res.status(401).json({ error: "Invalid username or password" });
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(401).json({ error: "Invalid username or password" });
    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '200h' });
    res.json({ message: "Login successful", token, user: { id: user._id, username: user.username } });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ error: "Server error during login" });
  }
});

app.post("/api/search", async (req, res) => {
  const { question } = req.body;
  if (!question) return res.status(400).json({ error: "Question field is required." });

  if (!isQueryIndiaRelated(question)) {
    console.log(`[BharatBot - Non-India Query] "${question}"`);
    return res.json({ result: "I primarily answer questions related to India. Please ask something about India.", source: "Scope Limit" });
  }

  if (!API_KEY || !CSE_ID) {
    console.warn("[BharatBot] Internet search attempted but API keys not configured.");
    return res.status(503).json({ result: "I'm configured to search the internet for answers, but the search service is not available right now. Please check configuration.", source: "Configuration Error" });
  }
  
  console.log(`[BharatBot] Searching internet for: "${question}"`);
  const internetResult = await searchAndScrapeInternet(question);

  if (internetResult.error) {
    return res.status(503).json({ result: internetResult.error, source: internetResult.source });
  }
  
  return res.json({ 
    result: internetResult.result, 
    source: internetResult.source, 
    sourceUrl: internetResult.sourceUrl, 
    sourceTitle: internetResult.sourceTitle 
  });
});

app.post("/api/bharat-ai/query", async (req, res) => {
  const { question } = req.body;
  if (!question) return res.status(400).json({ error: "Question field is required." });

  if (!isQueryIndiaRelated(question)) {
    console.log(`[BharatAI - Non-India Query] "${question}"`);
    return res.json({ result: "As Bharat AI, I can only provide information and search for topics related to India. Please rephrase your question.", source: "Bharat AI System - Scope Limit" });
  }

  let answer = searchBharatAIKB(question);
  let source = 'Bharat AI System (Internal Knowledge)';
  let sourceUrl = null;
  let sourceTitle = null;

  if (answer) {
    console.log(`[BharatAI - KB Hit] Question: "${question}"`);
    return res.json({ result: answer, source });
  } else {
    console.log(`[BharatAI - KB Miss, India-Related] Attempting internet search for: "${question}"`);
    if (API_KEY && CSE_ID) {
        const internetResult = await searchAndScrapeInternet(question);

        if (internetResult.error && internetResult.source === "Configuration Error") {
            answer = "My apologies, I couldn't find that in my current knowledge, and external search is not configured for me to look further.";
            source = 'Bharat AI System - No Match / No Fallback (Keys Missing)';
        } else if (internetResult.error) {
            console.error(`[BharatAI - Internet Search Error] ${internetResult.source}: ${internetResult.error}`);
            answer = `I tried searching the internet for "${question}", but encountered an issue: ${internetResult.error}. Please try again later or ask something else.`;
            source = `Bharat AI System - Internet Search Failed (${internetResult.source})`;
        } else {
            answer = internetResult.result;
            source = internetResult.source;
            sourceUrl = internetResult.sourceUrl;
            sourceTitle = internetResult.sourceTitle;

            const normalizedQuestionKey = normalizeTextForSearch(question);
            if (answer && !source.toLowerCase().includes("error") && 
                !source.toLowerCase().includes("no results") && 
                !source.toLowerCase().includes("link only") && 
                !source.toLowerCase().includes("not configured") &&
                !answer.toLowerCase().includes("could not fetch full content") &&
                !answer.toLowerCase().includes("no suitable paragraphs extracted")) {
                if (!bharatAIKnowledgeBase[normalizedQuestionKey]) {
                    bharatAIKnowledgeBase[normalizedQuestionKey] = answer;
                    console.log(`[BharatAI - Learned In-Memory] Question: "${normalizedQuestionKey}" (Source: ${source})`);
                }
            }
        }
    } else {
        console.log(`[BharatAI - No Match & No Internet Fallback Configured] Question: "${question}"`);
        answer = "My apologies, I couldn't find that in my current knowledge, and external search is not configured for me to look further.";
        source = 'Bharat AI System - No Match / No Fallback (Keys Missing)';
    }
    return res.json({ result: answer, source, sourceUrl, sourceTitle });
  }
});

app.post("/api/history", authenticateToken, async (req, res) => {
  const { question, answer, source } = req.body;
  const userId = req.user.userId;
  if (!question || !answer) return res.status(400).json({ error: "Question and answer are required to save history." });
  try {
    const newInteraction = new InteractionHistory({ userId, question, answer, source: source || 'unknown' });
    await newInteraction.save();
    res.status(201).json({ message: "Interaction saved successfully.", interaction: newInteraction });
  } catch (error) {
    console.error("Error saving interaction history:", error);
    res.status(500).json({ error: "Server error while saving interaction history." });
  }
});

app.get("/api/history", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const history = await InteractionHistory.find({ userId }).sort({ timestamp: -1 }).limit(50);
    res.json(history);
  } catch (error) {
    console.error("Error fetching interaction history:", error);
    res.status(500).json({ error: "Server error while fetching interaction history." });
  }
});

app.put("/api/users/me/email", authenticateToken, async (req, res) => {
  const { newEmail, currentPassword } = req.body;
  const userId = req.user.userId;
  if (!newEmail || !currentPassword) return res.status(400).json({ error: "New email and current password are required." });
  const emailRegex = /\S+@\S+\.\S+/;
  if (!emailRegex.test(newEmail)) return res.status(400).json({ error: "Invalid email format." });
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    const isPasswordMatch = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isPasswordMatch) return res.status(401).json({ error: "Incorrect current password." });
    const existingUserWithEmail = await User.findOne({ email: newEmail.toLowerCase() });
    if (existingUserWithEmail && existingUserWithEmail._id.toString() !== userId) {
      return res.status(409).json({ error: "This email address is already in use by another account." });
    }
    user.email = newEmail.toLowerCase();
    await user.save();
    res.json({ message: "Email updated successfully.", email: user.email });
  } catch (error) {
    console.error("Error updating email:", error);
    if (error.code === 11000) return res.status(409).json({ error: "This email address is already in use." });
    res.status(500).json({ error: "Server error while updating email." });
  }
});

app.get("/api/history/export", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const format = req.query.format || 'json';
  try {
    const historyItems = await InteractionHistory.find({ userId }).sort({ timestamp: 'asc' });
    if (historyItems.length === 0) return res.status(404).json({ message: "No history found to export." });
    let fileName = `bharatbot_history_${userId}`;
    let fileContent;
    let contentType;
    if (format === 'csv') {
      fileName += '.csv';
      contentType = 'text/csv';
      const header = `"Timestamp","Question","Answer","Source"${EOL}`;
      const rows = historyItems.map(item => 
        `"${new Date(item.timestamp).toISOString()}","${item.question.replace(/"/g, '""')}","${item.answer.replace(/"/g, '""')}","${(item.source || '').replace(/"/g, '""')}"`
      ).join(EOL);
      fileContent = header + rows;
    } else {
      fileName += '.json';
      contentType = 'application/json';
      fileContent = JSON.stringify(historyItems, null, 2);
    }
    res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);
    res.setHeader('Content-Type', contentType);
    res.send(fileContent);
  } catch (error) {
    console.error("Error exporting chat history:", error);
    res.status(500).json({ error: "Server error while exporting chat history." });
  }
});

app.post("/api/users/change-password", authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.userId;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: "Current and new password are required." });
  if (newPassword.length < 6) return res.status(400).json({ error: "New password must be at least 6 characters." });
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    const isMatch = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isMatch) return res.status(401).json({ error: "Incorrect current password." });
    const salt = await bcrypt.genSalt(10);
    user.passwordHash = await bcrypt.hash(newPassword, salt);
    await user.save();
    res.json({ message: "Password changed successfully." });
  } catch (error) {
    console.error("Error changing password:", error);
    res.status(500).json({ error: "Server error while changing password." });
  }
});

app.delete("/api/history/mine", authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const result = await InteractionHistory.deleteMany({ userId: userId });
    res.json({ message: `Successfully deleted ${result.deletedCount} history items.` });
  } catch (error) {
    console.error("Error clearing chat history:", error);
    res.status(500).json({ error: "Server error while clearing chat history." });
  }
});

app.delete("/api/users/me", authenticateToken, async (req, res) => {
  const { currentPassword } = req.body;
  const userId = req.user.userId;
  if (!currentPassword) return res.status(400).json({ error: "Current password is required to delete your account." });
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found." });
    const isPasswordMatch = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!isPasswordMatch) return res.status(401).json({ error: "Incorrect password. Account deletion failed." });
    await InteractionHistory.deleteMany({ userId: userId });
    await User.findByIdAndDelete(userId);
    res.json({ message: "Your account and all associated data have been successfully deleted." });
  } catch (error) {
    console.error("Error deleting account:", error);
    res.status(500).json({ error: "Server error while deleting account." });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  console.log(`MongoDB URI: ${MONGODB_URI ? 'Configured' : 'NOT CONFIGURED - Check .env'}`);
  console.log(`JWT_SECRET: ${JWT_SECRET ? 'Configured' : 'NOT CONFIGURED - Check .env'}`);
  if (API_KEY && CSE_ID) {
    console.log('Google Search API (for BharatBot & Bharat AI fallback) is configured.');
  } else {
    console.warn('Warning: Google API_KEY or CSE_ID is not set. BharatBot will not function reliably, and Bharat AI internet will be disabled.');
  }
});