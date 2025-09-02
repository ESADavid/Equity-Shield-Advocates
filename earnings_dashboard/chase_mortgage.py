from flask import Blueprint, Response

# Create a Blueprint for Chase Mortgage integration
router = Blueprint('chase_mortgage', __name__)

@router.route('/chase-mortgage')
def chase_mortgage_page():
    """
    Serve Chase Mortgage page embed or link.
    Note: Embedding external pages via iframe may be blocked by X-Frame-Options.
    So fallback to providing a direct link if embedding is not allowed.
    """
    chase_mortgage_url = 'https://www.chase.com/personal/mortgage/my-mortgage/home'

    html_content = f"""
    <html>
      <head>
        <title>Chase Mortgage Integration</title>
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
            <h1>Chase Mortgage Services</h1>
          </header>
          <iframe src="{chase_mortgage_url}" onerror="this.style.display='none'; document.getElementById('fallback').style.display='block';"></iframe>
          <div id="fallback" class="fallback-link" style="display:none;">
            <p>Embedding is not supported. Please visit the Chase Mortgage page directly:</p>
            <a href="{chase_mortgage_url}" target="_blank" class="button">Go to Chase Mortgage</a>
          </div>
        </div>
      </body>
    </html>
    """

    return Response(html_content, mimetype='text/html')
