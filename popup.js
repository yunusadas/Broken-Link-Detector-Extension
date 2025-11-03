// popup.js - Nihai Versiyon (Tüm Fonksiyonlar ve Düzeltmeler Dahil)

// API_BASE_URL, config.js dosyasından gelmelidir.

document.addEventListener('DOMContentLoaded', () => {

    // ----------------------------------------------------
    // 1. DOM ELEMENTLERİ
    // ----------------------------------------------------
    const authSection = document.getElementById('auth-section');
    const mainApp = document.getElementById('main-app');
    const authMessage = document.getElementById('auth-message');

    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const loginTab = document.getElementById('login-tab');
    const registerTab = document.getElementById('register-tab');

    const logoutButton = document.getElementById('logout-button');
    const userInfo = document.getElementById('user-info');
    const subscriptionInfo = document.getElementById('subscription-info');
    const upgradeButton = document.getElementById('upgrade-button');

    const scanTab = document.getElementById('scan-tab');
    const historyTab = document.getElementById('history-tab');
    const bulkTab = document.getElementById('bulk-tab');

    const scanContent = document.getElementById('scan-content');
    const historyContent = document.getElementById('history-content');
    const bulkScanContent = document.getElementById('bulk-scan-content');

    const scanForm = document.getElementById('scan-form');
    const scanMessage = document.getElementById('scan-message');
    const scanResultsSection = document.getElementById('scan-results-section');
    const scanSummary = document.getElementById('scan-summary');
    const redirectTableBody = document.getElementById('redirect-table-body');
    const userAgentSelect = document.getElementById('user-agent-select');
    const targetUrlInput = document.getElementById('target-url');
    const getCurrentUrlButton = document.getElementById('get-current-url-button');

    const premiumDetailsSection = document.getElementById('premium-details-section');
    const detailTitle = document.getElementById('detail-title');
    const headerDetails = document.getElementById('header-details');

    const scanAllLinksButton = document.getElementById('scan-all-links-button');
    const fullScanResultsSection = document.getElementById('full-scan-results-section');
    const fullScanSummaryList = document.getElementById('full-scan-summary-list');

    const bulkScanForm = document.getElementById('bulk-scan-form');
    const bulkUrlsInput = document.getElementById('bulk-urls');
    const bulkScanMessage = document.getElementById('bulk-scan-message');
    const bulkResultsSection = document.getElementById('bulk-results-section');
    const bulkSummaryList = document.getElementById('bulk-summary-list');

    const historyMessage = document.getElementById('history-message');
    const historyTableBody = document.getElementById('history-table-body');

    const historyActions = document.getElementById('history-actions');
    const clearHistoryButton = document.getElementById('clear-history-button');

    const exportButtons = document.getElementById('export-buttons');
    const exportCsvButton = document.getElementById('export-csv-button');
    const exportJsonButton = document.getElementById('export-json-button');

    let IS_PREMIUM = 0;
    let SCAN_CREDITS = 0;
    let LAST_SCAN_RESULT = null;


    // ----------------------------------------------------
    // 2. YARDIMCI FONKSİYONLAR
    // ----------------------------------------------------

    const showMessage = (element, message, type) => {
        element.textContent = message;
        element.className = `message ${type}`;
        element.style.display = 'block';
        element.style.marginTop = '10px';
    };
    const normalizeUrl = (url) => {
        let cleanUrl = url.trim();

        // 1. URL boşsa veya sadece boşluksa direkt geri dön
        if (!cleanUrl) return '';

        // 2. Eğer URL "http://" veya "https://" ile başlıyorsa, olduğu gibi bırak
        if (cleanUrl.startsWith('http://') || cleanUrl.startsWith('https://')) {
            return cleanUrl;
        }

        // 3. Protokol yoksa, varsayılan olarak "https://" ekle
        return `https://${cleanUrl}`;
    };
    const getIndexabilityInsights = (result) => {
        let html = '';

        if (IS_PREMIUM === 0) {
            return '<p class="premium-insight-placeholder">İndeksleme Analizi: <span style="color: #eab308; font-weight: 600;">PREMIUM</span></p>';
        }

        // 200 OK olmayan yanıtlar için indekse edilemez kabul et
        if (parseInt(result.final_status) !== 200) {
            return `<p><strong>İndeks Durumu:</strong> <span style="color: #dc2626; font-weight: 700;">❌ İndekslenemez</span> (Nihai Kod: ${result.final_status})</p>`;
        }


        // API'den gelen veriyi al, yoksa varsayılan değerler ata
        const indexStatus = result.indexability_status ? result.indexability_status.toLowerCase() : 'index, follow';
        const canonicalUrl = result.final_url || 'Yok';

        // 1. İndeksleme Durumu (X-Robots-Tag / Meta Robots)
        let indexHtml;
        if (indexStatus.includes('noindex')) {
            indexHtml = `<span style="color: #dc2626; font-weight: 700;">⛔ ${indexStatus.toUpperCase()}</span>`;
        } else if (indexStatus.includes('nofollow') && !indexStatus.includes('noindex')) {
            indexHtml = `<span style="color: #f59e0b; font-weight: 700;">⚠️ ${indexStatus.toUpperCase()}</span>`;
        } else {
            indexHtml = `<span style="color: #16a34a; font-weight: 700;">✅ ${indexStatus.toUpperCase()}</span>`;
        }

        html += `<p><strong>İndeks Durumu:</strong> ${indexHtml} ${!result.indexability_status ? '(Varsayılan/Başlık Yok)' : ''}</p>`;

        // 2. Canonical URL
        let canonicalHtml;
        if (canonicalUrl === 'Yok') {
            canonicalHtml = `Yok (${result.final_url})`;
        } else if (canonicalUrl.trim() !== result.final_url.trim()) {
            canonicalHtml = `<span style="color: #f59e0b; font-weight: 600;">🔄 ${canonicalUrl}</span> (Farklı)`;
        } else {
            canonicalHtml = canonicalUrl;
        }

        html += `<p><strong>Canonical URL:</strong> ${canonicalHtml}</p>`;

        return html;
    };
    const deleteHistoryItem = async (scanId, rowElement) => {
        if (!confirm('Bu tarama kaydını silmek istediğinizden emin misiniz?')) {
            return;
        }

        const tokenData = await chrome.storage.local.get('jwtToken');
        const jwtToken = tokenData.jwtToken;

        if (!jwtToken) {
            showMessage(historyMessage, 'Yetkilendirme hatası.', 'error');
            handleLogout();
            return;
        }

        const apiUrl = `${API_BASE_URL}/scan/delete_item.php`;

        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jwtToken}`
                },
                body: JSON.stringify({ scan_id: scanId })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                rowElement.remove();
                showMessage(historyMessage, data.message || 'Kayıt başarıyla silindi.', 'success');

                if (historyTableBody.children.length === 0) {
                    showMessage(historyMessage, 'Henüz hiç tarama geçmişiniz yok.', 'info');
                    // Tablo boşalınca toplu silme ve export butonlarını gizle
                    if (historyActions) historyActions.style.display = 'none';
                    if (exportButtons) exportButtons.style.display = 'none';
                }

            } else {
                showMessage(historyMessage, data.message || 'Silme işleminde bir hata oluştu.', 'error');
            }

        } catch (error) {
            console.error('Silme API İletişim Hatası:', error);
            showMessage(historyMessage, 'Sunucuya bağlanılamadı.', 'error');
        }
    };
    const handleClearHistory = async () => {
        if (!confirm('Geçmişinizdeki TÜM kayıtları silmek istediğinizden emin misiniz? Bu işlem geri alınamaz!')) {
            return;
        }

        const tokenData = await chrome.storage.local.get('jwtToken');
        const jwtToken = tokenData.jwtToken;

        if (!jwtToken) {
            showMessage(historyMessage, 'Yetkilendirme hatası.', 'error');
            handleLogout();
            return;
        }

        const apiUrl = `${API_BASE_URL}/scan/clear_history.php`;
        showMessage(historyMessage, 'Tüm geçmiş siliniyor...', 'info');


        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jwtToken}`
                },
                body: JSON.stringify({})
            });

            const data = await response.json();

            if (response.ok && data.success) {
                // Tablonun içini tamamen boşalt
                historyTableBody.innerHTML = '';
                // Tabloyu gizle (veya action butonlarını)
                if (historyActions) historyActions.style.display = 'none';
                if (exportButtons) exportButtons.style.display = 'none';
                showMessage(historyMessage, data.message || 'Tüm geçmiş başarıyla temizlendi.', 'success');
                showMessage(historyMessage, 'Henüz hiç tarama geçmişiniz yok.', 'info');


            } else {
                showMessage(historyMessage, data.message || 'Toplu silme işleminde bir hata oluştu.', 'error');
            }

        } catch (error) {
            console.error('Toplu Silme API İletişim Hatası:', error);
            showMessage(historyMessage, 'Sunucuya bağlanılamadı.', 'error');
        }
    };
    const getStatusCodeTag = (status) => {
        const statusCode = parseInt(status);
        let statusClass;
        if (statusCode >= 200 && statusCode < 300) {
            statusClass = 'status-200';
        } else if (statusCode >= 300 && statusCode < 400) {
            statusClass = 'status-3xx';
        } else if (statusCode >= 400 && statusCode < 500) {
            statusClass = 'status-4xx';
        } else if (statusCode >= 500) {
            statusClass = 'status-5xx';
        } else {
            statusClass = '';
        }
        return `<span class="status-code-tag ${statusClass}">${status}</span>`;
    };
    const updateSubscriptionUI = (username, isPremium, credits) => {
        userInfo.textContent = `Merhaba, ${username}!`;
        IS_PREMIUM = isPremium;
        SCAN_CREDITS = credits;

        let infoText = '';
        if (isPremium == 1) {
            infoText = '<span style="color: #17236a; font-weight: 700;">PREMIUM Kullanıcı</span> (Limitsiz Tarama)';
            bulkTab.style.display = 'block';
            upgradeButton.style.display = 'none';
            if (scanAllLinksButton) scanAllLinksButton.style.display = 'inline-block';
            // Abonelik güncellendiğinde, History sekmesinde ise action butonlarını göster
            if (historyContent.style.display === 'block' && historyTableBody.children.length > 0) {
                if (historyActions) historyActions.style.display = 'flex';
                if (exportButtons) exportButtons.style.display = 'flex';
            }
        } else {
            // Kredi Gösterimi
            const creditColor = credits > 0 ? '#17236a' : '#dc2626';
            infoText = `Kalan Kredi: <span style="font-weight: 700; color: ${creditColor};">${credits}</span>`;
            bulkTab.style.display = 'none';
            upgradeButton.style.display = 'inline-block';
            if (scanAllLinksButton) scanAllLinksButton.style.display = 'none';
            // Abonelik güncellendiğinde, Premium değilse action butonlarını gizle
            if (historyActions) historyActions.style.display = 'none';
            if (exportButtons) exportButtons.style.display = 'none';
        }
        subscriptionInfo.innerHTML = infoText;

        updateAgentSelectState();
    };
    const updateAgentSelectState = () => {
        userAgentSelect.querySelectorAll('option').forEach(option => {
            if (option.value !== 'default') {
                if (IS_PREMIUM === 0) {
                    option.disabled = true;
                    if (userAgentSelect.value !== 'default') {
                        userAgentSelect.value = 'default';
                    }
                } else {
                    option.disabled = false;
                }
            }
        });
    };
    const showDetails = (step, index) => {
        premiumDetailsSection.style.display = 'block';

        if (IS_PREMIUM === 0) {
            headerDetails.textContent = 'Bu alan sadece Premium kullanıcılar için mevcuttur.';
            detailTitle.textContent = `Adım ${index + 1} Detayları (PREMIUM)`;

            // PREMIUM UYARISI GELDİĞİNDE KAYDIRMA
            premiumDetailsSection.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });

            return;
        }

        detailTitle.textContent = `Adım ${index + 1}: ${step.url}`;

        let headerText = '';
        if (step.headers) {
            for (const key in step.headers) {
                if (key === 'Status-Line') {
                    headerText += `${key}: ${step.headers[key]}\n`;
                } else {
                    headerText += `${key}: ${step.headers[key]}\n`;
                }
            }
        } else {
            headerText = 'Başlık bilgisi bulunamadı.';
        }

        headerDetails.textContent = headerText;


        // DETAY GÖSTERİLDİĞİNDE KAYDIRMA
        premiumDetailsSection.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    };
    const displayAuthSection = () => {
        mainApp.style.display = 'none';
        authSection.style.display = 'block';
        authMessage.style.display = 'none';
        scanMessage.style.display = 'none';
    };
    const displayAppSection = async (username) => {
        authSection.style.display = 'none';
        mainApp.style.display = 'block';

        // 1. Yerel Depolamada Hızlı Veri Kontrolü (handleAuth'da kaydedilen)
        const storedInfo = await chrome.storage.local.get(['isPremium', 'scanCredits']);

        let is_premium = storedInfo.isPremium;
        let scan_credits = storedInfo.scanCredits;

        // 2. Eğer yerel depolamada premium veya kredi bilgisi yoksa, API'den çek
        // (Bu, ilk yükleme veya depolamanın temizlendiği senaryodur)
        if (is_premium === undefined || scan_credits === undefined) {
            const apiInfo = await fetchSubscriptionInfo();
            is_premium = apiInfo.is_premium;
            scan_credits = apiInfo.scan_credits;

            // API'den çektiysek, bir sonraki yükleme için depolamaya kaydedelim
            await chrome.storage.local.set({
                isPremium: is_premium,
                scanCredits: scan_credits
            });
        }

        // 3. UI'yı en güncel verilerle güncelle
        updateSubscriptionUI(username, is_premium, scan_credits);

        switchAppTab('scan');
    };
    const switchAuthTab = (showLogin) => {
        if (showLogin) {
            loginForm.style.display = 'block';
            registerForm.style.display = 'none';
            loginTab.classList.add('active');
            registerTab.classList.remove('active');
        } else {
            loginForm.style.display = 'none';
            registerForm.style.display = 'block';
            registerTab.classList.add('active');
            loginTab.classList.remove('active');
        }
        authMessage.style.display = 'none';
    };
    const switchAppTab = (target) => {
        [scanContent, historyContent, bulkScanContent].forEach(c => c.style.display = 'none');
        [scanTab, historyTab, bulkTab].forEach(t => t.classList.remove('active'));

        switch (target) {
            case 'scan':
                scanContent.style.display = 'block';
                scanTab.classList.add('active');
                break;
            case 'history':
                historyContent.style.display = 'block';
                historyTab.classList.add('active');
                loadHistory();
                break;
            case 'bulk':
                bulkScanContent.style.display = 'block';
                bulkTab.classList.add('active');
                bulkResultsSection.style.display = 'none';
                bulkScanMessage.style.display = 'none';
                break;
        }
    };
    const displayScanResults = (result, targetBody = redirectTableBody, targetSummary = scanSummary) => {
        targetBody.innerHTML = '';
        targetSummary.innerHTML = '';
        premiumDetailsSection.style.display = 'none';
        LAST_SCAN_RESULT = result;

        let summaryHtml = `
            <p><strong>Başlangıç URL:</strong> ${result.initial_url}</p>
            <p><strong>Nihai URL:</strong> ${result.final_url}</p>
            <p><strong>Nihai Durum Kodu:</strong> ${getStatusCodeTag(result.final_status)}</p>
            <p><strong>Adım Sayısı:</strong> ${result.chain.length}</p>
        `;

        summaryHtml += '---<br>' + getIndexabilityInsights(result);

        targetSummary.innerHTML = summaryHtml;

        result.chain.forEach((step, index) => {
            const row = targetBody.insertRow();

            row.insertCell().textContent = index + 1;
            row.insertCell().innerHTML = getStatusCodeTag(step.status);

            const latencyCell = row.insertCell();
            if (IS_PREMIUM === 1 && step.latency_ms !== undefined) {
                latencyCell.textContent = `${step.latency_ms} ms`;
            } else {
                latencyCell.textContent = IS_PREMIUM === 1 ? '-' : 'PREMIUM';
                latencyCell.style.color = IS_PREMIUM === 1 ? 'inherit' : '#eab308';
            }

            row.insertCell().textContent = step.url;
            row.insertCell().textContent = step.redirect_to || '-';

            const detailCell = row.insertCell();
            const detailButton = document.createElement('button');
            detailButton.textContent = 'Gör';
            detailButton.className = 'btn btn-detail';
            detailButton.addEventListener('click', () => {
                showDetails(step, index);
            });
            detailCell.appendChild(detailButton);
        });

        scanResultsSection.style.display = 'block';

        // OTOMATİK KAYDIRMA DÜZELTMESİ: Sonuçlar gösterildiğinde otomatik olarak kaydır.
        const scanResultsElement = document.getElementById('scan-results-section');
        if (scanResultsElement) {
            scanResultsElement.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    };

    // ----------------------------------------------------
    // 3. AUTHENTICATION (GİRİŞ/KAYIT/ÇIKIŞ) MANTIĞI
    // ----------------------------------------------------

    const handleAuth = async (e, endpoint) => {
        e.preventDefault();

        const formId = endpoint === 'login' ? 'login-form' : 'register-form';
        const form = document.getElementById(formId);

        const usernameInput = form.querySelector('input[type="text"]');
        const passwordInput = form.querySelector('input[type="password"]');

        const username = usernameInput.value;
        const password = passwordInput.value;

        if (!username || !password) {
            showMessage(authMessage, 'Kullanıcı adı ve şifre zorunludur.', 'error');
            return;
        }

        const apiUrl = `${API_BASE_URL}/auth/${endpoint}.php`;
        showMessage(authMessage, 'İşlem yapılıyor...', 'info');

        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showMessage(authMessage, data.message, 'success');

                if (endpoint === 'login' && data.token) {

                    // 1. JWT ve kullanıcı adını kaydet
                    await chrome.storage.local.set({ jwtToken: data.token, username: username });

                    // 2. Abonelik bilgilerini API'den hemen çek
                    const { is_premium, scan_credits } = await fetchSubscriptionInfo();

                    // 3. Premium ve kredi bilgilerini de yerel depolamaya kaydet
                    // Bu, displayAppSection'ın en güncel veriyi hemen kullanmasını sağlar.
                    await chrome.storage.local.set({
                        isPremium: is_premium,
                        scanCredits: scan_credits
                    });

                    // UI'yi en güncel verilerle güncelle
                    displayAppSection(username);

                } else if (endpoint === 'register') {
                    switchAuthTab(true); // Giriş sekmesine yönlendir
                }
            } else {
                const message = data.message || 'Bir hata oluştu.';
                showMessage(authMessage, message, 'error');
            }
        } catch (error) {
            console.error('API İletişim Hatası:', error);
            showMessage(authMessage, 'Sunucuya bağlanılamadı. CORS veya ağ bağlantısını kontrol edin.', 'error');
        }
    };

    const handleLogout = async () => {
        await chrome.storage.local.remove(['jwtToken', 'username']);
        displayAuthSection();
    };

    const checkAuthStatus = async () => {
        const tokenData = await chrome.storage.local.get(['jwtToken', 'username']);
        if (tokenData.jwtToken && tokenData.username) {
            displayAppSection(tokenData.username);
        } else {
            displayAuthSection();
        }
    };

    const fetchSubscriptionInfo = async () => {
        const tokenData = await chrome.storage.local.get('jwtToken');
        const jwtToken = tokenData.jwtToken;

        if (!jwtToken) return { is_premium: 0, scan_credits: 0 };

        const apiUrl = `${API_BASE_URL}/user/info.php`;

        try {
            const response = await fetch(apiUrl, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`
                }
            });

            const data = await response.json();

            if (response.ok && data.success) {
                return {
                    is_premium: data.is_premium,
                    scan_credits: data.scan_credits
                };
            } else {
                console.error("Abonelik bilgisi çekilemedi:", data.message);
                return { is_premium: 0, scan_credits: 0 };
            }
        } catch (error) {
            console.error('Abonelik API İletişim Hatası:', error);
            return { is_premium: 0, scan_credits: 0 };
        }
    };


    // ----------------------------------------------------
    // 4. GEÇMİŞ VE EXPORT MANTIĞI (GÜNCELLENDİ)
    // ----------------------------------------------------

    const loadHistory = async () => {
        historyTableBody.innerHTML = '';
        showMessage(historyMessage, 'Geçmiş yükleniyor...', 'info');

        const tokenData = await chrome.storage.local.get('jwtToken');
        const jwtToken = tokenData.jwtToken;

        if (!jwtToken) {
            showMessage(historyMessage, 'Yetkilendirme hatası.', 'error');
            handleLogout();
            return;
        }

        const apiUrl = `${API_BASE_URL}/scan/history.php`;

        try {
            const response = await fetch(apiUrl, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`
                }
            });

            const data = await response.json();

            if (response.ok && data.success) {

                if (data.history.length === 0) {
                    showMessage(historyMessage, 'Henüz hiç tarama geçmişiniz yok.', 'info');
                    if (historyActions) historyActions.style.display = 'none';
                    if (exportButtons) exportButtons.style.display = 'none';
                    return;
                }

                historyMessage.style.display = 'none';

                // Geçmiş varsa action butonlarını göster
                if (historyActions) historyActions.style.display = 'flex';
                // Premium kullanıcı değilse export butonlarını gizle
                if (IS_PREMIUM === 0 && exportButtons) exportButtons.style.display = 'none';
                else if (IS_PREMIUM === 1 && exportButtons) exportButtons.style.display = 'flex';


                data.history.forEach((scan) => {
                    const row = historyTableBody.insertRow();

                    const date = new Date(scan.created_at);
                    const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
                    row.insertCell().textContent = formattedDate;

                    row.insertCell().textContent = scan.url;

                    const result = JSON.parse(scan.result_json);
                    console.log(scan.result_json);
                    row.insertCell().innerHTML = getStatusCodeTag(result.final_status);

                    // GÖR Butonu
                    const detailCell = row.insertCell();
                    const detailButton = document.createElement('button');
                    detailButton.textContent = 'Gör';
                    detailButton.className = 'btn btn-detail';

                    // Geçmişten gelen kaydı gösterince ana sekmeye kaydırılacak
                    detailButton.addEventListener('click', () => {
                        switchAppTab('scan');
                        displayScanResults(result);
                    });
                    detailCell.appendChild(detailButton);

                    // SİL Butonu (EKLENEN KISIM)
                    const deleteCell = row.insertCell();
                    const deleteButton = document.createElement('button');
                    deleteButton.textContent = 'Sil';
                    deleteButton.className = 'btn btn-delete';
                    deleteButton.addEventListener('click', () => {
                        // Tekli silme fonksiyonunu tetikle
                        deleteHistoryItem(scan.id, row);
                    });
                    deleteCell.appendChild(deleteButton);
                });

            } else {
                showMessage(historyMessage, data.message || 'Geçmiş yüklenirken bir hata oluştu.', 'error');
            }

        } catch (error) {
            console.error('Geçmiş API İletişim Hatası:', error);
            showMessage(historyMessage, 'Sunucuya bağlanılamadı.', 'error');
        }
    };

    const handleExport = async (format) => {
        const tokenData = await chrome.storage.local.get('jwtToken');
        const jwtToken = tokenData.jwtToken;

        if (!jwtToken || IS_PREMIUM === 0) {
            alert('Bu işlem için Premium abonelik gereklidir.');
            return;
        }

        exportCsvButton.disabled = true;
        exportJsonButton.disabled = true;

        showMessage(historyMessage, `${format.toUpperCase()} dosyası hazırlanıyor...`, 'info');

        const exportUrl = `${API_BASE_URL}/scan/history.php?format=${format}`;

        try {
            const response = await fetch(exportUrl, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`
                }
            });

            if (response.status === 402) {
                const data = await response.json();
                showMessage(historyMessage, data.message || 'Yetkiniz yok.', 'error');
                return;
            }

            if (!response.ok) {
                throw new Error('Dosya indirme başarısız oldu.');
            }

            const blob = await response.blob();
            const contentDisposition = response.headers.get('Content-Disposition');

            let filename = `scan_history_export.${format === 'json_export' ? 'json' : 'csv'}`;
            if (contentDisposition) {
                const matches = contentDisposition.match(/filename="(.+?)"/);
                if (matches && matches[1]) {
                    filename = matches[1];
                }
            }

            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            showMessage(historyMessage, `${filename} başarıyla indirildi.`, 'success');

        } catch (error) {
            console.error('Export Hatası:', error);
            showMessage(historyMessage, `İndirme sırasında bir hata oluştu: ${error.message}`, 'error');
        } finally {
            exportCsvButton.disabled = false;
            exportJsonButton.disabled = false;
        }
    };


    // ----------------------------------------------------
    // 5. URL TARAMA MANTIĞI VE AKTİF SEKME URL'Sİ ALMA
    // ----------------------------------------------------

    const getCurrentTabUrl = () => {
        if (!chrome.tabs) {
            showMessage(scanMessage, 'chrome.tabs API\'si bulunamadı. Uzantı ortamında çalıştığınızdan emin olun.', 'error');
            return;
        }

        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs && tabs.length > 0) {
                const url = tabs[0].url;

                if (url && url.startsWith('http')) {
                    targetUrlInput.value = url;
                    showMessage(scanMessage, 'Aktif sekme URL\'si başarıyla alındı.', 'success');
                } else {
                    showMessage(scanMessage, 'Aktif sayfa URL\'si alınamadı (Güvenlik veya özel Chrome sayfası).', 'error');
                }
            } else {
                showMessage(scanMessage, 'Aktif sekme bulunamadı.', 'error');
            }
        });
    };


    const handleScanAllLinks = async () => {
        if (IS_PREMIUM === 0) {
            showMessage(scanMessage, 'Bu özellik yalnızca PREMIUM aboneler için geçerlidir.', 'error');
            return;
        }

        const url = normalizeUrl(targetUrlInput.value); // Protokol normalizasyonu
        const selectedAgent = userAgentSelect.value;

        if (!url) {
            showMessage(scanMessage, 'Lütfen geçerli bir başlangıç URL\'si girin.', 'error');
            return;
        }

        showMessage(scanMessage, 'Tüm sayfa linkleri taranıyor... Bu işlem zaman alabilir.', 'info');
        fullScanResultsSection.style.display = 'none';
        fullScanSummaryList.innerHTML = '';
        scanResultsSection.style.display = 'none'; // Tekli sonuçları gizleyebiliriz

        const tokenData = await chrome.storage.local.get(['jwtToken', 'username']);
        const jwtToken = tokenData.jwtToken;
        const username = tokenData.username;

        if (!jwtToken) {
            showMessage(scanMessage, 'Yetkilendirme hatası.', 'error');
            handleLogout();
            return;
        }

        const apiUrl = `${API_BASE_URL}/scan/crawl_links.php`; // Yeni API uç noktamız

        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jwtToken}`
                },
                body: JSON.stringify({ url: url, user_agent: selectedAgent })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showMessage(scanMessage, data.message || `Toplam ${data.results.length} link tarandı.`, 'success');

                // Sonuçları Göster
                displayFullScanResults(data.results);

                const { is_premium, scan_credits } = await fetchSubscriptionInfo();
                updateSubscriptionUI(username, is_premium, scan_credits);

            } else if (response.status === 402) {
                showMessage(scanMessage, data.message, 'error');
            } else {
                showMessage(scanMessage, data.message || 'Link tarama başarısız oldu.', 'error');
            }

        } catch (error) {
            console.error('Link Tarama API İletişim Hatası:', error);
            showMessage(scanMessage, 'Sunucuya bağlanılamadı veya ağ hatası oluştu.', 'error');
        }
    };

// Yeni Sonuç Gösterim Fonksiyonu
    const displayFullScanResults = (results) => {
        fullScanSummaryList.innerHTML = '';

        results.forEach(item => {
            // ... (Status ve mesaj hesaplama kısmı aynı kalır) ...
            const status = item.result ? item.result.final_status : (item.error ? 'HATA' : 'Bilinmiyor');

            let message;
            let itemClass = 'info';

            if (item.error) {
                message = item.error;
                itemClass = 'error';
            } else if (status >= 400) {
                message = `❌ HATA KODU: ${status}`;
                itemClass = 'error';
            } else if (status >= 300) {
                message = `⚠️ YÖNLENDİRME ZİNCİRİ: ${status}`;
                itemClass = 'warning';
            } else {
                message = `✅ OK: ${status}`;
                itemClass = 'success';
            }

            // **KRİTİK DEĞİŞİKLİK BURADA BAŞLAR**

            // 1. Kapsayıcı LI elementini oluştur
            const li = document.createElement('li');
            li.className = `full-scan-item ${itemClass}`;

            // 2. İçeriği güvenli bir şekilde ayarla
            li.innerHTML = `
            <strong>${item.initial_url}</strong><br>
            <span>${message}</span>
        `;

            // 3. Butonu programatik olarak oluştur (innerHTML kullanmadan)
            const detailButton = document.createElement('button');
            detailButton.textContent = 'Zinciri Gör';
            detailButton.className = 'btn btn-detail btn-tiny';

            if (item.result) {
                const resultJsonString = JSON.stringify(item.result);
                const safeJsonString = encodeURIComponent(resultJsonString);

                // 4. JSON'u doğrudan nitelik olarak ayarla (tırnak karışmasını engeller)
                detailButton.setAttribute('data-link-result', safeJsonString);

                // 5. Olay dinleyiciyi butona ekle
                detailButton.addEventListener('click', (e) => {
                    const safeData = e.target.getAttribute('data-link-result');

                    try {
                        const decodedData = decodeURIComponent(safeData);
                        const result = JSON.parse(decodedData);

                        switchAppTab('scan');
                        displayScanResults(result);
                        showMessage(scanMessage, 'Aşağıda seçtiğiniz linkin yönlendirme detayları gösterilmektedir.', 'info');

                    } catch (error) {
                        console.error("Detay JSON ayrıştırma hatası:", error);
                        showMessage(scanMessage, "Detay verisi işlenirken beklenmedik bir hata oluştu.", 'error');
                    }
                });
            } else {
                detailButton.disabled = true;
            }

            // 6. Butonu LI'ye ekle
            li.appendChild(detailButton);
            fullScanSummaryList.appendChild(li);
        });

        fullScanResultsSection.style.display = 'block';

        // Olay Dinleyicisini kaldırdık, çünkü butonlar oluşturulurken eklendi.

        fullScanResultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };

    // Tekli Tarama
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const rawUrl = targetUrlInput.value;
        const selectedAgent = userAgentSelect.value;

        const url = normalizeUrl(rawUrl);

        if (!url) {
            showMessage(scanMessage, 'Lütfen geçerli bir URL girin.', 'error');
            return;
        }

        if (selectedAgent !== 'default' && IS_PREMIUM === 0) {
            showMessage(scanMessage, 'Masaüstü/Mobil tarama, Premium özelliktir. Lütfen hesabınızı yükseltin.', 'error');
            userAgentSelect.value = 'default';
            return;
        }

        if (SCAN_CREDITS <= 0 && IS_PREMIUM === 0) {
            showMessage(scanMessage, 'Krediniz kalmadı. Lütfen hesabınızı yükseltin.', 'error');
            return;
        }

        showMessage(scanMessage, 'Tarama başlatılıyor...', 'info');
        scanResultsSection.style.display = 'none';

        const tokenData = await chrome.storage.local.get(['jwtToken', 'username']);
        const jwtToken = tokenData.jwtToken;
        const username = tokenData.username;

        if (!jwtToken) {
            showMessage(scanMessage, 'Yetkilendirme hatası. Lütfen tekrar giriş yapın.', 'error');
            handleLogout();
            return;
        }

        const apiUrl = `${API_BASE_URL}/scan/resolve.php`;

        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jwtToken}`
                },
                body: JSON.stringify({ url: url, user_agent: selectedAgent })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showMessage(scanMessage, data.message, 'success');
                displayScanResults(data.result);

                const { is_premium, scan_credits } = await fetchSubscriptionInfo();
                updateSubscriptionUI(username, is_premium, scan_credits);

            } else if (response.status === 402) {
                showMessage(scanMessage, data.message, 'error');
            } else {
                const message = data.message || 'Tarama başarısız oldu.';
                if (response.status === 401) {
                    showMessage(scanMessage, 'Oturum süreniz doldu. Lütfen tekrar giriş yapın.', 'error');
                    handleLogout();
                }
                showMessage(scanMessage, message, 'error');
            }

        } catch (error) {
            console.error('Tarama API İletişim Hatası:', error);
            showMessage(scanMessage, 'Sunucuya bağlanılamadı veya ağ hatası oluştu.', 'error');
        }
    });

    // Toplu Tarama Fonksiyonu
    bulkScanForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (IS_PREMIUM === 0) {
            showMessage(bulkScanMessage, 'Bu özellik yalnızca PREMIUM aboneler için geçerlidir.', 'error');
            return;
        }

        bulkResultsSection.style.display = 'none';
        bulkSummaryList.innerHTML = '';

        const rawUrls = bulkUrlsInput.value.split('\n').filter(url => url.trim() !== '');
        if (rawUrls.length === 0) {
            showMessage(bulkScanMessage, 'Lütfen taranacak URL\'leri girin.', 'error');
            return;
        }
        const urls = rawUrls.map(url => normalizeUrl(url)).filter(url => url !== '');

        if (urls.length === 0) {
            showMessage(bulkScanMessage, 'Girilen URL\'lerden geçerli olan bulunamadı.', 'error');
            return;
        }

        showMessage(bulkScanMessage, `Toplu tarama başlatılıyor... ${rawUrls.length} URL işlenecek.`, 'info');

        const tokenData = await chrome.storage.local.get(['jwtToken', 'username']);
        const jwtToken = tokenData.jwtToken;
        const username = tokenData.username;

        if (!jwtToken) {
            showMessage(bulkScanMessage, 'Yetkilendirme hatası.', 'error');
            handleLogout();
            return;
        }

        const apiUrl = `${API_BASE_URL}/scan/bulk_resolve.php`;

        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${jwtToken}`
                },
                body: JSON.stringify({ urls: urls })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                showMessage(bulkScanMessage, data.message, 'success');

                bulkSummaryList.innerHTML = '<h4>Taranan URL\'ler:</h4>';
                data.results.forEach(item => {
                    const status = item.result ? item.result.final_status : 'HATA';
                    const message = item.error || `Nihai Durum: ${getStatusCodeTag(status)}`;

                    const div = document.createElement('div');
                    div.className = 'message ' + (item.error ? 'error' : 'success');
                    div.innerHTML = `<strong>${item.initial_url}</strong><br>${message}`;
                    bulkSummaryList.appendChild(div);
                });

                bulkResultsSection.style.display = 'block';

                const { is_premium, scan_credits } = await fetchSubscriptionInfo();
                updateSubscriptionUI(username, is_premium, scan_credits);

            } else if (response.status === 402) {
                showMessage(bulkScanMessage, data.message, 'error');
            } else {
                showMessage(bulkScanMessage, data.message || 'Toplu tarama başarısız oldu.', 'error');
            }

        } catch (error) {
            console.error('Toplu Tarama API İletişim Hatası:', error);
            showMessage(bulkScanMessage, 'Sunucuya bağlanılamadı veya ağ hatası oluştu.', 'error');
        }
    });


    // ----------------------------------------------------
    // 6. OLAY DİNLEYİCİLER (Başlatma)
    // ----------------------------------------------------

    if (scanAllLinksButton) {
        scanAllLinksButton.addEventListener('click', handleScanAllLinks); // YENİ ÖZELLİK
    }

    loginTab.addEventListener('click', () => switchAuthTab(true));
    registerTab.addEventListener('click', () => switchAuthTab(false));

    loginForm.addEventListener('submit', (e) => handleAuth(e, 'login'));
    registerForm.addEventListener('submit', (e) => handleAuth(e, 'register'));

    logoutButton.addEventListener('click', handleLogout);

    scanTab.addEventListener('click', () => switchAppTab('scan'));
    historyTab.addEventListener('click', () => switchAppTab('history'));
    bulkTab.addEventListener('click', () => switchAppTab('bulk'));

    exportCsvButton.addEventListener('click', () => handleExport('csv'));
    exportJsonButton.addEventListener('click', () => handleExport('json_export'));

    clearHistoryButton.addEventListener('click', handleClearHistory);

    upgradeButton.addEventListener('click', () => {
        alert("Hesabınızı yükseltme sayfasına yönlendirileceksiniz. Ödeme entegrasyonundan sonra aktif olacak.");
    });

    getCurrentUrlButton.addEventListener('click', getCurrentTabUrl);

    checkAuthStatus();
});