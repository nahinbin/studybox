#!/usr/bin/env python3
"""
Script to initialize sample MMU links in the database.
Run this script to add sample MMU links for demonstration purposes.
"""

import os
import sys
from dotenv import load_dotenv

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, assignmenet_db, MMULink

def create_sample_mmu_links():
    """Create sample MMU links for demonstration purposes"""
    sample_links = [
        {
            'title': 'MMU Portal',
            'url': 'https://portal.mmu.edu.my',
            'description': 'Main student portal for MMU',
            'display_order': 1
        },
        {
            'title': 'Student Email',
            'url': 'https://mail.mmu.edu.my',
            'description': 'Access your MMU email',
            'display_order': 2
        },
        {
            'title': 'Library System',
            'url': 'https://library.mmu.edu.my',
            'description': 'MMU digital library',
            'display_order': 3
        },
        {
            'title': 'Academic Calendar',
            'url': 'https://www.mmu.edu.my/academic-calendar',
            'description': 'Important dates and events',
            'display_order': 4
        },
        {
            'title': 'Course Registration',
            'url': 'https://portal.mmu.edu.my/course-registration',
            'description': 'Register for courses',
            'display_order': 5
        },
        {
            'title': 'Exam Results',
            'url': 'https://portal.mmu.edu.my/exam-results',
            'description': 'View your exam results',
            'display_order': 6
        }
    ]
    
    with app.app_context():
        created_count = 0
        for link_data in sample_links:
            # Check if link already exists
            existing_link = MMULink.query.filter_by(title=link_data['title']).first()
            if not existing_link:
                favicon_url = f"https://www.google.com/s2/favicons?domain={link_data['url']}&sz=32"
                
                new_link = MMULink(
                    title=link_data['title'],
                    url=link_data['url'],
                    favicon_url=favicon_url,
                    description=link_data['description'],
                    display_order=link_data['display_order'],
                    is_active=True
                )
                
                assignmenet_db.session.add(new_link)
                created_count += 1
        
        assignmenet_db.session.commit()
        print(f"Successfully created {created_count} sample MMU links!")
        
        if created_count == 0:
            print("All sample MMU links already exist in the database.")

if __name__ == '__main__':
    load_dotenv()
    create_sample_mmu_links()
