"""
OpenAI Integration Module for Advanced Email Analysis
Uses GPT-4 for enhanced spam and phishing detection
"""

import os
from typing import Dict, Any
from openai import OpenAI

# Initialize OpenAI client
client = None
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if OPENAI_API_KEY:
    client = OpenAI(api_key=OPENAI_API_KEY)


def analyze_email_with_openai(sender: str, subject: str, body: str) -> Dict[str, Any]:
    """
    Analyze email using OpenAI GPT-4 for advanced threat detection

    Args:
        sender: Email sender address
        subject: Email subject line
        body: Email body content

    Returns:
        Dictionary containing analysis results with prediction, confidence, and reasoning
    """

    if not client or not OPENAI_API_KEY:
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "reasoning": "OpenAI API key not configured",
            "success": False
        }

    try:
        prompt = f"""Analyze this email for spam and phishing threats. Return your analysis in JSON format.

Email Details:
- Sender: {sender}
- Subject: {subject}
- Body: {body[:1000]}  # Limit body to first 1000 chars

Provide your analysis in this exact JSON format:
{{
    "prediction": "safe" or "spam" or "phishing",
    "confidence": float between 0.0 and 1.0,
    "reasoning": "Brief explanation of your analysis",
    "threat_indicators": ["list of specific threat indicators found"],
    "recommendation": "Recommended action"
}}

Consider these factors:
1. Suspicious sender domains or spoofed addresses
2. Urgency tactics or social engineering
3. Requests for sensitive information
4. Suspicious links or attachments
5. Grammar and spelling errors
6. Impersonation attempts
7. Unusual requests for money or credentials
"""

        response = client.chat.completions.create(
            model="gpt-4-turbo-preview",
            messages=[
                {
                    "role": "system",
                    "content": "You are an advanced email security analyst specializing in spam and phishing detection. Analyze emails and provide detailed threat assessments."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=500,
            response_format={"type": "json_object"}
        )

        # Parse OpenAI response
        import json
        analysis = json.loads(response.choices[0].message.content)

        # Ensure required fields exist
        if "prediction" not in analysis:
            analysis["prediction"] = "unknown"
        if "confidence" not in analysis:
            analysis["confidence"] = 0.0
        if "reasoning" not in analysis:
            analysis["reasoning"] = "Analysis completed"

        analysis["success"] = True
        return analysis

    except Exception as e:
        print(f"OpenAI analysis error: {e}")
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "reasoning": f"Error during analysis: {str(e)}",
            "success": False
        }


def combine_predictions(ml_prediction: str, ml_confidence: float,
                       openai_prediction: str, openai_confidence: float) -> Dict[str, Any]:
    """
    Combine ML model and OpenAI predictions for final verdict

    Args:
        ml_prediction: Prediction from the ML model
        ml_confidence: Confidence score from the ML model
        openai_prediction: Prediction from OpenAI
        openai_confidence: Confidence score from OpenAI

    Returns:
        Dictionary with combined prediction and confidence
    """

    # Weight: 40% ML model, 60% OpenAI (OpenAI is more reliable)
    ml_weight = 0.4
    openai_weight = 0.6

    # Map predictions to numerical scores
    prediction_scores = {
        "safe": 0,
        "ham": 0,
        "spam": 1,
        "phishing": 2
    }

    ml_score = prediction_scores.get(ml_prediction.lower(), 0)
    openai_score = prediction_scores.get(openai_prediction.lower(), 0)

    # Calculate weighted average
    combined_score = (ml_score * ml_weight) + (openai_score * openai_weight)
    combined_confidence = (ml_confidence * ml_weight) + (openai_confidence * openai_weight)

    # Determine final prediction
    if combined_score < 0.5:
        final_prediction = "safe"
    elif combined_score < 1.5:
        final_prediction = "spam"
    else:
        final_prediction = "phishing"

    # If both models strongly agree, increase confidence
    if ml_prediction.lower() == openai_prediction.lower():
        combined_confidence = min(1.0, combined_confidence * 1.1)

    return {
        "prediction": final_prediction,
        "confidence": combined_confidence,
        "ml_prediction": ml_prediction,
        "ml_confidence": ml_confidence,
        "openai_prediction": openai_prediction,
        "openai_confidence": openai_confidence
    }
