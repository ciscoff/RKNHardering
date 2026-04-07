package com.notcvnt.rknhardering

import android.graphics.Typeface
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.notcvnt.rknhardering.checker.VpnCheckRunner
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.Verdict
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var btnRunCheck: MaterialButton
    private lateinit var progressBar: ProgressBar
    private lateinit var cardGeoIp: MaterialCardView
    private lateinit var cardDirect: MaterialCardView
    private lateinit var cardIndirect: MaterialCardView
    private lateinit var cardVerdict: MaterialCardView
    private lateinit var iconGeoIp: ImageView
    private lateinit var iconDirect: ImageView
    private lateinit var iconIndirect: ImageView
    private lateinit var statusGeoIp: TextView
    private lateinit var statusDirect: TextView
    private lateinit var statusIndirect: TextView
    private lateinit var findingsGeoIp: LinearLayout
    private lateinit var findingsDirect: LinearLayout
    private lateinit var findingsIndirect: LinearLayout
    private lateinit var cardBypass: MaterialCardView
    private lateinit var iconBypass: ImageView
    private lateinit var statusBypass: TextView
    private lateinit var textBypassProgress: TextView
    private lateinit var findingsBypass: LinearLayout
    private lateinit var iconVerdict: ImageView
    private lateinit var textVerdict: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        bindViews()

        btnRunCheck.setOnClickListener {
            runCheck()
        }
    }

    private fun bindViews() {
        btnRunCheck = findViewById(R.id.btnRunCheck)
        progressBar = findViewById(R.id.progressBar)
        cardGeoIp = findViewById(R.id.cardGeoIp)
        cardDirect = findViewById(R.id.cardDirect)
        cardIndirect = findViewById(R.id.cardIndirect)
        cardVerdict = findViewById(R.id.cardVerdict)
        iconGeoIp = findViewById(R.id.iconGeoIp)
        iconDirect = findViewById(R.id.iconDirect)
        iconIndirect = findViewById(R.id.iconIndirect)
        statusGeoIp = findViewById(R.id.statusGeoIp)
        statusDirect = findViewById(R.id.statusDirect)
        statusIndirect = findViewById(R.id.statusIndirect)
        findingsGeoIp = findViewById(R.id.findingsGeoIp)
        findingsDirect = findViewById(R.id.findingsDirect)
        findingsIndirect = findViewById(R.id.findingsIndirect)
        cardBypass = findViewById(R.id.cardBypass)
        iconBypass = findViewById(R.id.iconBypass)
        statusBypass = findViewById(R.id.statusBypass)
        textBypassProgress = findViewById(R.id.textBypassProgress)
        findingsBypass = findViewById(R.id.findingsBypass)
        iconVerdict = findViewById(R.id.iconVerdict)
        textVerdict = findViewById(R.id.textVerdict)
    }

    private fun runCheck() {
        btnRunCheck.isEnabled = false
        progressBar.visibility = View.VISIBLE
        hideCards()

        // Show bypass card immediately with scanning status
        cardBypass.visibility = View.VISIBLE
        iconBypass.setImageResource(R.drawable.ic_help)
        statusBypass.text = "Сканирование..."
        statusBypass.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
        textBypassProgress.visibility = View.VISIBLE
        textBypassProgress.text = "Подготовка..."
        findingsBypass.removeAllViews()

        lifecycleScope.launch {
            val result = VpnCheckRunner.run(this@MainActivity) { progress ->
                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                    textBypassProgress.text = "${progress.phase}: ${progress.detail}"
                }
            }
            progressBar.visibility = View.GONE
            btnRunCheck.isEnabled = true
            displayResult(result)
        }
    }

    private fun hideCards() {
        cardGeoIp.visibility = View.GONE
        cardDirect.visibility = View.GONE
        cardIndirect.visibility = View.GONE
        cardBypass.visibility = View.GONE
        cardVerdict.visibility = View.GONE
    }

    private fun displayResult(result: CheckResult) {
        displayCategory(
            result.geoIp, cardGeoIp, iconGeoIp, statusGeoIp, findingsGeoIp
        )
        displayCategory(
            result.directSigns, cardDirect, iconDirect, statusDirect, findingsDirect
        )
        displayCategory(
            result.indirectSigns, cardIndirect, iconIndirect, statusIndirect, findingsIndirect
        )
        displayBypass(result.bypassResult)
        displayVerdict(result.verdict)
    }

    private fun displayCategory(
        category: CategoryResult,
        card: MaterialCardView,
        icon: ImageView,
        status: TextView,
        findingsContainer: LinearLayout
    ) {
        card.visibility = View.VISIBLE

        if (category.detected) {
            icon.setImageResource(R.drawable.ic_warning)
            status.text = "Обнаружено"
            status.setTextColor(ContextCompat.getColor(this, R.color.finding_detected))
        } else {
            icon.setImageResource(R.drawable.ic_check_circle)
            status.text = "Чисто"
            status.setTextColor(ContextCompat.getColor(this, R.color.finding_ok))
        }

        findingsContainer.removeAllViews()
        for (finding in category.findings) {
            findingsContainer.addView(createFindingView(finding))
        }
    }

    private fun createFindingView(finding: Finding): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 4.dp, 0, 4.dp)
        }

        val indicator = TextView(this).apply {
            text = if (finding.detected) "\u26A0" else "\u2713"
            setTextColor(
                ContextCompat.getColor(
                    this@MainActivity,
                    if (finding.detected) R.color.finding_detected else R.color.finding_ok
                )
            )
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 8.dp, 0)
        }

        val description = TextView(this).apply {
            text = finding.description
            textSize = 13f
            val tv = TypedValue()
            this@MainActivity.theme.resolveAttribute(android.R.attr.textColorPrimary, tv, true)
            setTextColor(ContextCompat.getColor(this@MainActivity, tv.resourceId))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        row.addView(indicator)
        row.addView(description)
        return row
    }

    private fun displayBypass(bypass: BypassResult) {
        cardBypass.visibility = View.VISIBLE
        textBypassProgress.visibility = View.GONE

        if (bypass.detected) {
            iconBypass.setImageResource(R.drawable.ic_warning)
            statusBypass.text = "Обнаружено"
            statusBypass.setTextColor(ContextCompat.getColor(this, R.color.finding_detected))
        } else {
            iconBypass.setImageResource(R.drawable.ic_check_circle)
            statusBypass.text = "Чисто"
            statusBypass.setTextColor(ContextCompat.getColor(this, R.color.finding_ok))
        }

        findingsBypass.removeAllViews()
        for (finding in bypass.findings) {
            findingsBypass.addView(createFindingView(finding))
        }
    }

    private fun displayVerdict(verdict: Verdict) {
        cardVerdict.visibility = View.VISIBLE

        when (verdict) {
            Verdict.NOT_DETECTED -> {
                iconVerdict.setImageResource(R.drawable.ic_check_circle)
                textVerdict.text = "Обход не выявлен"
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_green))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_green_bg)
                )
            }
            Verdict.NEEDS_REVIEW -> {
                iconVerdict.setImageResource(R.drawable.ic_help)
                textVerdict.text = "Требуется дополнительная проверка"
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_yellow))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_yellow_bg)
                )
            }
            Verdict.DETECTED -> {
                iconVerdict.setImageResource(R.drawable.ic_error)
                textVerdict.text = "Обход выявлен"
                textVerdict.setTextColor(ContextCompat.getColor(this, R.color.verdict_red))
                cardVerdict.setCardBackgroundColor(
                    ContextCompat.getColor(this, R.color.verdict_red_bg)
                )
            }
        }
    }

    private val Int.dp: Int
        get() = (this * resources.displayMetrics.density).toInt()
}
