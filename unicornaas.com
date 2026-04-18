<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unicorn as a Service Oy — Business Lab</title>
    <meta
      name="description"
      content="Unicorn as a Service Oy is a business lab and venture studio building scalable software businesses that transform outdated paradigms."
    />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
      rel="stylesheet"
    />
    <style>
      :root {
        --bg: #13151a;
        --panel: #1c1e24;
        --muted: #9aa4b2;
        --text: #f4f5f8;
        --brand: #5b8fc9;
        --ring: 0 0 0 3px rgba(255, 255, 255, 0.2);
        --radius: 18px;
        --shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
        /* Tighter vertical rhythm */
        --space-xs: 6px;
        --space-sm: 10px;
        --space-md: 16px;
        --space-lg: 24px;
        --space-xl: 32px;
      }

      * {
        box-sizing: border-box;
      }

      html {
        scroll-behavior: smooth;
      }

      html,
      body {
        height: 100%;
      }

      body {
        margin: 0;
        font-family:
          Inter,
          -apple-system,
          BlinkMacSystemFont,
          "Segoe UI",
          Roboto,
          sans-serif;
        color: var(--text);
        font-size: 15px;
        line-height: 1.5;
        letter-spacing: -0.01em;
        -webkit-font-smoothing: antialiased;
        background:
          radial-gradient(
            ellipse 80% 50% at 50% -20%,
            rgba(255, 255, 255, 0.03),
            transparent 50%
          ),
          linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
          linear-gradient(
            90deg,
            rgba(255, 255, 255, 0.015) 1px,
            transparent 1px
          ),
          var(--bg);
        background-size:
          100% 100%,
          32px 32px,
          32px 32px,
          100% 100%;
      }

      @media (prefers-reduced-motion: reduce) {
        html {
          scroll-behavior: auto;
        }
      }

      @media (prefers-reduced-motion: reduce) {
        body {
          background:
            radial-gradient(
              ellipse 80% 50% at 50% -20%,
              rgba(255, 255, 255, 0.03),
              transparent 50%
            ),
            var(--bg);
          background-size: 100% 100%;
        }
      }

      a {
        color: var(--brand);
        text-decoration: none;
      }
      a:hover {
        text-decoration: underline;
      }
      a:focus-visible {
        outline: 2px solid var(--muted);
        outline-offset: 2px;
      }

      .wrapper {
        max-width: 1100px;
        margin: 0 auto;
        padding: 0 clamp(28px, 5vw, 56px);
      }

      /* Top navigation */
      header {
        position: sticky;
        top: 0;
        z-index: 10;
        background: rgba(30, 33, 40, 0.85);
        backdrop-filter: saturate(120%) blur(10px);
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
      }
      .nav {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding: 10px 0;
      }
      .logo {
        padding-left: 10px;
        display: flex;
        align-items: center;
        gap: 10px;
        font-weight: 600;
        font-size: 15px;
        letter-spacing: -0.02em;
      }
      .logo-mark {
        width: 30px;
        height: 30px;
        border-radius: 8px;
        position: relative;
        background: conic-gradient(
          from 180deg,
          #ff6a00,
          #ffd100,
          #27e1a0,
          #00c3ff,
          #6a5cff,
          #ff00c8,
          #ff6a00
        );
        box-shadow:
          0 0 0 2px rgba(255, 255, 255, 0.06),
          0 8px 22px rgba(0, 0, 0, 0.2);
        filter: saturate(0.55);
      }
      nav a {
        color: var(--text);
        opacity: 0.9;
        margin: 0 10px;
        font-weight: 500;
        font-size: 14px;
        letter-spacing: -0.01em;
      }
      nav a:hover {
        opacity: 1;
      }
      .cta {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 34px;
        gap: 10px;
        padding: 8px 20px;
        background: var(--panel);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        box-shadow: var(--shadow);
        color: var(--text);
      }
      .cta:hover {
        background: #2e323c;
        text-decoration: none;
      }
      .cta:focus-visible {
        outline: 2px solid var(--muted);
        outline-offset: 2px;
      }

      /* Hero — Linear-style: tight headline, compact spacing */
      .hero {
        position: relative;
        padding: 40px 0 44px;
      }
      .title-emphasis {
        text-decoration: underline;
        text-decoration-color: var(--muted);
        text-underline-offset: 4px;
        text-decoration-thickness: 1.5px;
      }
      .rainbow-text {
        background: linear-gradient(90deg, #fadfac, #b9d9e3, #f9abe8, #f5caab);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
      }
      .headline {
        font-size: clamp(28px, 5.5vw, 48px);
        line-height: 1.08;
        font-weight: 700;
        letter-spacing: -0.03em;
        margin: 0;
      }
      .sub {
        color: var(--muted);
        font-size: clamp(15px, 2.2vw, 18px);
        line-height: 1.55;
        max-width: 720px;
        margin-top: var(--space-md);
      }

      .hero-card {
        margin-top: var(--space-lg);
        background: var(--panel);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: var(--radius);
        padding: var(--space-lg);
        box-shadow: var(--shadow);
      }

      .badges {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        justify-content: center;
      }
      .badge {
        padding: 8px 12px;
        border-radius: 999px;
        border: 1px solid rgba(255, 255, 255, 0.06);
        background: rgba(255, 255, 255, 0.03);
        color: var(--text);
      }

      /* Sections — tighter vertical rhythm (Linear-style) */
      section {
        padding: 36px 0 40px;
      }
      h2 {
        font-size: clamp(20px, 2.5vw, 24px);
        font-weight: 600;
        letter-spacing: -0.025em;
        line-height: 1.2;
        margin: 0 0 var(--space-sm);
      }
      .card h3 {
        font-size: 1rem;
        font-weight: 600;
        letter-spacing: -0.02em;
        line-height: 1.3;
        margin-top: 0;
      }
      p {
        color: #e4e8ef;
        margin: 0 0 var(--space-sm);
        font-size: 15px;
        line-height: 1.55;
      }
      p:last-child {
        margin-bottom: 0;
      }

      .grid {
        display: grid;
        grid-template-columns: repeat(12, 1fr);
        gap: var(--space-md);
      }

      .card {
        background: var(--panel);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: var(--radius);
        padding: var(--space-md);
        box-shadow: var(--shadow);
      }

      /* Businesses */
      .biz {
        display: flex;
        align-items: center;
        gap: var(--space-md);
      }
      .biz img {
        width: 64px;
        height: 64px;
        border-radius: 14px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        background: var(--bg);
      }

      .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 44px;
        gap: 8px;
        padding: 10px 18px;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        background: rgba(255, 255, 255, 0.05);
        color: var(--text);
        font-weight: 600;
      }
      .btn:hover {
        background: rgba(255, 255, 255, 0.08);
        text-decoration: none;
      }
      .btn:focus-visible {
        outline: 2px solid var(--muted);
        outline-offset: 2px;
      }

      /* Footer */
      footer {
        padding: 28px 0 40px;
        color: var(--muted);
      }
      .rainbow-line {
        height: 2px;
        background: linear-gradient(
          90deg,
          #f8ccad,
          #f9e799,
          #61e4b6,
          #b9d9e3,
          #cbc7f9,
          #f9abe8,
          #f5caab
        );
        opacity: 0.8;
        border-radius: 2px;
      }

      /* Tiny utilities */
      .muted {
        color: var(--muted);
      }
      .center {
        text-align: center;
      }
      .mt-2 {
        margin-top: var(--space-sm);
      }
      .mt-4 {
        margin-top: var(--space-lg);
      }

      @media (max-width: 780px) {
        nav {
          display: none;
        }
        .grid {
          grid-template-columns: 1fr;
        }
      }
    </style>
  </head>
  <body>
    <header>
      <div class="wrapper nav">
        <div class="logo">
          <!-- <span class="logo-mark" aria-hidden="true"></span>-->
          Unicorn as a Service Oy
        </div>
        <nav>
          <a class="cta" href="mailto:hello@unicornaas.com">Email us</a>
        </nav>
      </div>
    </header>

    <main class="wrapper">
      <section class="hero" id="home">
        <h1 class="headline">
          A <span class="rainbow-text">business lab</span> for paradigm-shifting
          software ventures
        </h1>
        <p class="sub">
          Unicorn as a Service Oy designs, incubates and launches new software
          businesses that transform outdated paradigms. We blend decades of
          experience in technology, product and business transformation to
          create ventures that scale from day one.
        </p>
      </section>

      <section id="about">
        <div class="grid">
          <div class="card" style="grid-column: span 7">
            <h2>What we do</h2>
            <p>
              We originate and validate opportunities and build the first
              version with a senior, hands-on team.
            </p>
            <p>
              Our specific focus is on transforming outdated paradigms - using
              sound, visuals and AI.
            </p>
          </div>
          <div class="card" style="grid-column: span 5">
            <h2>Backed by experience</h2>
            <p>
              Our founders have led complex businesses and developed large-scale
              systems first-hand.
            </p>
            <p>
              We believe in the mix of technology depth and realistic and
              ambitious business approach.
            </p>
          </div>
        </div>
      </section>

      <section id="approach">
        <div class="grid">
          <div class="card" style="grid-column: span 4">
            <h3 class="rainbow-text">01 — Technology</h3>
            <p>Modern tech stacks and thoughtful AI integration.</p>
          </div>
          <div class="card" style="grid-column: span 4">
            <h3 class="rainbow-text">02 — Business</h3>
            <p>We target niche markets and experiment-driven growth.</p>
            <p>We shift the old paradigm to a new one.</p>
          </div>
          <div class="card" style="grid-column: span 4">
            <h3 class="rainbow-text">03 — Values</h3>
            <p>Inclusion and sustainability.</p>
          </div>
        </div>
      </section>

      <!--
      <section id="businesses">
        <h2>Businesses</h2>
        <div class="card mt-2">
          <div class="biz">
            <img alt="Droplyn logo" src="droplyn-logo-transparent.png" />
            <div>
              <h3 style="margin: 0">Droplyn Board</h3>
              <p class="muted" style="margin: 0.25rem 0 0.5rem">
                A tool for product managers to manage customer needs visually —
                assisted by AI.
              </p>
              <a
                class="btn"
                href="https://droplyn.io"
                target="_blank"
                rel="noopener"
                >Visit droplyn.io</a
              >
            </div>
          </div>
        </div>
      </section>
      -->

      <section id="contact">
        <div class="card">
          <h2>Contact</h2>
          <p>
            Interested in partnering or building with us? Throw us an email.
          </p>
          <p class="mt-2">
            <a class="cta" href="mailto:hello@unicornaas.com">Email us</a>
          </p>
        </div>
      </section>

      <div class="rainbow-line"></div>
      <footer class="center">
        <p class="mt-4">
          © <span id="y"></span> Unicorn as a Service Oy (FI3269214-4) · All
          rights reserved.
        </p>
      </footer>
    </main>

    <script>
      // Set year
      document.getElementById("y").textContent = new Date().getFullYear();
    </script>
  </body>
</html>
