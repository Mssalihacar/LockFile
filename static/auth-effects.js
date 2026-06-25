document.addEventListener("DOMContentLoaded", () => {
    const canvas = document.getElementById("networkCanvas");

    if (!canvas) {
        return;
    }

    const container = canvas.parentElement;
    const ctx = canvas.getContext("2d");

    let width = 0;
    let height = 0;

    const mouse = {
        x: null,
        y: null,
        radius: 140
    };

    const particles = [];
    const clickBursts = [];

    const PARTICLE_COUNT = 70;

    function resizeCanvas() {
        const rect = container.getBoundingClientRect();

        width = rect.width;
        height = rect.height;

        canvas.width = width;
        canvas.height = height;
    }

    class Particle {
        constructor() {
            this.reset(true);
        }

        reset(initial = false) {
            this.x = Math.random() * width;
            this.y = Math.random() * height;

            this.vx = (Math.random() - 0.5) * 0.55;
            this.vy = (Math.random() - 0.5) * 0.55;

            this.size = Math.random() * 2.2 + 1;
            this.alpha = Math.random() * 0.45 + 0.20;

            if (!initial) {
                this.x = Math.random() * width;
                this.y = Math.random() * height;
            }
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0 || this.x > width) {
                this.vx *= -1;
            }

            if (this.y < 0 || this.y > height) {
                this.vy *= -1;
            }

            if (mouse.x !== null && mouse.y !== null) {
                const dx = this.x - mouse.x;
                const dy = this.y - mouse.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < mouse.radius && dist > 0) {
                    const force = (mouse.radius - dist) / mouse.radius;
                    this.x += (dx / dist) * force * 1.3;
                    this.y += (dy / dist) * force * 1.3;
                }
            }
        }

        draw() {
            ctx.beginPath();
            ctx.fillStyle = `rgba(190, 210, 255, ${this.alpha})`;
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
        }
    }

    class BurstParticle {
        constructor(x, y) {
            this.x = x;
            this.y = y;

            const angle = Math.random() * Math.PI * 2;
            const speed = Math.random() * 2.4 + 0.8;

            this.vx = Math.cos(angle) * speed;
            this.vy = Math.sin(angle) * speed;

            this.life = 55;
            this.size = Math.random() * 2 + 1.2;
            this.alpha = 0.9;
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            this.vx *= 0.985;
            this.vy *= 0.985;

            this.life -= 1;
            this.alpha = Math.max(this.life / 55, 0);
        }

        draw() {
            ctx.beginPath();
            ctx.fillStyle = `rgba(181, 167, 223, ${this.alpha})`;
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
        }
    }

    function initParticles() {
        particles.length = 0;

        for (let i = 0; i < PARTICLE_COUNT; i++) {
            particles.push(new Particle());
        }
    }

    function drawConnections() {
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 115) {
                    const alpha = (1 - dist / 115) * 0.18;

                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(210, 220, 255, ${alpha})`;
                    ctx.lineWidth = 1;
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
    }

    function drawMouseLinks() {
        if (mouse.x === null || mouse.y === null) {
            return;
        }

        for (let i = 0; i < particles.length; i++) {
            const dx = particles[i].x - mouse.x;
            const dy = particles[i].y - mouse.y;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < 130) {
                const alpha = (1 - dist / 130) * 0.24;

                ctx.beginPath();
                ctx.strokeStyle = `rgba(156, 188, 236, ${alpha})`;
                ctx.lineWidth = 1;
                ctx.moveTo(mouse.x, mouse.y);
                ctx.lineTo(particles[i].x, particles[i].y);
                ctx.stroke();
            }
        }
    }

    function createBurst(x, y) {
        for (let i = 0; i < 22; i++) {
            clickBursts.push(new BurstParticle(x, y));
        }
    }

    function animate() {
        ctx.clearRect(0, 0, width, height);

        for (let i = 0; i < particles.length; i++) {
            particles[i].update();
            particles[i].draw();
        }

        drawConnections();
        drawMouseLinks();

        for (let i = clickBursts.length - 1; i >= 0; i--) {
            clickBursts[i].update();
            clickBursts[i].draw();

            if (clickBursts[i].life <= 0) {
                clickBursts.splice(i, 1);
            }
        }

        requestAnimationFrame(animate);
    }

    container.addEventListener("mousemove", (event) => {
        const rect = canvas.getBoundingClientRect();
        mouse.x = event.clientX - rect.left;
        mouse.y = event.clientY - rect.top;
    });

    container.addEventListener("mouseleave", () => {
        mouse.x = null;
        mouse.y = null;
    });

    container.addEventListener("click", (event) => {
        const rect = canvas.getBoundingClientRect();
        const x = event.clientX - rect.left;
        const y = event.clientY - rect.top;
        createBurst(x, y);
    });

    window.addEventListener("resize", () => {
        resizeCanvas();
        initParticles();
    });

    resizeCanvas();
    initParticles();
    animate();
});