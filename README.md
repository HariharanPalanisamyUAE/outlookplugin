Email Security Monitor - Outlook Plugin


colab notebook for AI model - https://colab.research.google.com/drive/1C8GgH9_BexFJlsRc5ij4B9dmIha0bI-6?usp=sharing
seamlessly with Microsoft Outlook to detect spam and phishing emails in real-time using machine learning.
Features

    Real-time Email Analysis: Instant detection of spam and phishing emails

    Outlook Integration: Seamless plugin experience within Outlook

    Machine Learning Powered: Advanced ML models for accurate threat detection

    SOC Dashboard: Comprehensive security operations center dashboard

    Threat Intelligence: Database-driven threat analysis and reporting

    Multi-platform Support: Works on Outlook Desktop, Web, and Mobile

    Automated Actions: Delete, move to junk, or report threats automatically

    Confidence Scoring: AI-driven confidence levels for each detection


step: 1
    python -m venv venv 
    
step: 2
    source venv/bin/activate

step: 3
    pip install -r requirements.txt

step: 4
    config env with postgres connection values
step: 5
    uvicorn main:app --reload

step: 6
    modify manifest.xml for outloog add ins update
step: 7
    upload addins in your outlook plugin



Docker will be updated soon


MIT License

Copyright (c) 2025 Hariharan Palanisamy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

_



