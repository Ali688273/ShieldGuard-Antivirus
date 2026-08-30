package com.shieldguard.antivirus

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class ThreatAdapter(private val items: List<ThreatItem>) : RecyclerView.Adapter<ThreatAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val title: TextView = view.findViewById(R.id.itemTitle)
        val desc: TextView = view.findViewById(R.id.itemDesc)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_threat, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.title.text = item.title
        holder.desc.text = item.description

        if (item.isDanger) {
            holder.title.setTextColor(Color.parseColor("#EF4444"))
        } else {
            holder.title.setTextColor(Color.parseColor("#10B981"))
        }
    }

    override fun getItemCount() = items.size
}
