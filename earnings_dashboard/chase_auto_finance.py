from flask import Blueprint, Response

# Create a Blueprint for Chase Auto Finance integration
router = Blueprint('chase_auto_finance', __name__)

@router.route('/')
def chase_auto_finance_page():
    """
    Serve Chase Auto Finance page embed or link.
    Note: Embedding external pages via iframe may be blocked by X-Frame-Options.
    So fallback to providing a direct link if embedding is not allowed.
    """
    chase_auto_finance_url = 'https://www.chase.com/personal/auto-financing'

    html_content = f"""
    <html>
      <head>
        <title>Chase Auto Finance Integration</title>
        <style>
          body, html {{
            margin: 0; padding: 0; height: 100%;
            font-family: Arial, sans-serif;
          }}
          .container {{
            height: 100%;
            display: flex;
            flex-direction: column;
          }}
          header {{
            background-color: #00457c;
            color: white;
            padding: 1rem;
            text-align: center;
          }}
          iframe {{
            flex-grow: 1;
            border: none;
            width: 100%;
          }}
          .fallback-link {{
            margin: 2rem;
            text-align: center;
          }}
          a.button {{
            background-color: #00457c;
            color: white;
            padding: 0.75rem 1.5rem;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
          }}
        </style>
      </head>
      <body>
        <div class="container">
          <header>
            <h1>Chase Auto Finance Services</h1>
          </header>
          <iframe src="{chase_auto_finance_url}" onerror="this.style.display='none'; document.getElementById('fallback').style.display='block';"></iframe>
          <div id="fallback" class="fallback-link" style="display:none;">
            <p>Embedding is not supported. Please visit the Chase Auto Finance page directly:</p>
            <a href="{chase_auto_finance_url}" target="_blank" class="button">Go to Chase Auto Finance</a>
          </div>
        </div>
      </body>
    </html>
    """

    return Response(html_content, mimetype='text/html')
